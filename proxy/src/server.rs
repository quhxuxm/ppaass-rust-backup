use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use log::{error, info};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

use crate::config::ProxyConfiguration;
use crate::transport::{TcpTransport, TcpTransportSnapshot, TcpTransportStatus};

const CONFIG_FILE_PATH: &str = "ppaass-proxy.toml";
pub const LOCAL_ADDRESS: [u8; 4] = [0u8; 4];

const AGENT_PUBLIC_KEY_PATH: &str = "AgentPublicKey.pem";
const PROXY_PRIVATE_KEY_PATH: &str = "ProxyPrivateKey.pem";


pub struct Server {
    master_runtime: Runtime,
    worker_runtime: Arc<Runtime>,
    configuration: Arc<ProxyConfiguration>,
    transports: Arc<RwLock<HashMap<String, TcpTransportSnapshot>>>,
}


impl Server {
    pub fn new() -> Result<Self> {
        let mut config_file = File::open(CONFIG_FILE_PATH)?;
        let mut config_file_content = String::new();
        config_file.read_to_string(&mut config_file_content)?;
        let proxy_server_config = toml::from_str::<ProxyConfiguration>(&config_file_content)
            .with_context(|| "Fail to parse proxy configuration file.")?;
        log4rs::init_file(
            proxy_server_config.log_config().as_ref().unwrap(),
            Default::default(),
        )
            .with_context(|| "Fail to initialize proxy configuration file.")?;
        let mut master_runtime_builder = tokio::runtime::Builder::new_multi_thread();
        master_runtime_builder.worker_threads(
            proxy_server_config
                .master_thread_number()
                .with_context(|| "Can not get worker threads number from proxy configuration.")?,
        );
        master_runtime_builder.max_blocking_threads(
            proxy_server_config
                .max_blocking_threads()
                .with_context(|| "Can not get max blocking threads number from proxy configuration.")?,
        );
        master_runtime_builder.thread_name("proxy-master");
        master_runtime_builder.thread_keep_alive(Duration::from_secs(
            proxy_server_config
                .thread_timeout()
                .with_context(|| "Can not get thread timeout from proxy configuration.")?,
        ));
        master_runtime_builder.enable_all();
        let master_runtime = master_runtime_builder
            .build()
            .with_context(|| "Fail to build init tokio runtime.")?;
        let mut worker_runtime_builder = tokio::runtime::Builder::new_multi_thread();
        worker_runtime_builder.worker_threads(
            proxy_server_config
                .worker_thread_number()
                .with_context(|| "Can not get relay thread number from proxy configuration.")?,
        );
        worker_runtime_builder.max_blocking_threads(
            proxy_server_config
                .max_blocking_threads()
                .with_context(|| "Can not get max blocking threads number from proxy configuration.")?,
        );
        worker_runtime_builder.thread_name("proxy-worker");
        worker_runtime_builder.thread_keep_alive(Duration::from_secs(
            proxy_server_config
                .thread_timeout()
                .with_context(|| "Can not get thread time out from proxy configuration.")?,
        ));
        worker_runtime_builder.enable_all();
        let worker_runtime = worker_runtime_builder.build()?;
        Ok(Self {
            master_runtime,
            worker_runtime: Arc::new(worker_runtime),
            configuration: Arc::new(proxy_server_config),
            transports: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn run(&self) -> Result<()> {
        let agent_public_key = std::fs::read_to_string(Path::new(AGENT_PUBLIC_KEY_PATH)).expect("Fail to read agent public key.");
        let proxy_private_key = std::fs::read_to_string(Path::new(PROXY_PRIVATE_KEY_PATH)).expect("Fail to read agent public key.");
        let proxy_server_config = self.configuration.clone();
        let worker_runtime = self.worker_runtime.clone();
        let (transport_info_sender, mut transport_info_receiver) = tokio::sync::mpsc::channel::<TcpTransportSnapshot>(32);
        let transports = self.transports.clone();
        self.master_runtime.spawn(async move {
            loop {
                let transport_snapshot = transport_info_receiver.recv().await;
                match transport_snapshot {
                    None => {
                        continue;
                    }
                    Some(snapshot) => {
                        let mut transport_write_lock = transports.write();
                        match transport_write_lock.as_mut() {
                            Err(e) => {
                                error!("Fail to acquire write lock on transports, error: {:#?}", e);
                            }
                            Ok(transports) => {
                                if snapshot.status == TcpTransportStatus::Closed {
                                    info!("Remove closed transport, transport: [{}]", snapshot.id);
                                    transports.remove(snapshot.id.as_str());
                                    continue;
                                }
                                info!("Add transport, transport: [{}]", snapshot.id);
                                transports.insert(snapshot.id.clone(), snapshot);
                            }
                        };
                    }
                }
            }
        });

        let transports = self.transports.clone();
        self.master_runtime.spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                println!("######Transport list on proxy: \n\n");
                {
                    let transports_read_lock = transports.read();
                    match transports_read_lock {
                        Err(e) => {
                            continue;
                        }
                        Ok(lock) => {
                            for (_, snapshot) in lock.iter() {
                                println!("{:#?}", snapshot)
                            }
                        }
                    }
                }
                println!("\n\n");
                interval.tick().await;
            }
        });

        self.master_runtime.block_on(async move {
            let local_port = proxy_server_config.port().unwrap();
            let local_ip = IpAddr::from(LOCAL_ADDRESS);
            let local_address = SocketAddr::new(local_ip, local_port);
            let tcp_listener = TcpListener::bind(local_address)
                .await
                .unwrap_or_else(|e| panic!("Fail to start proxy because of error, error: {:#?}", e));
            //Start to processing client protocol
            info!("Success to bind TCP server on port: [{}]", local_port);

            loop {
                let agent_connection_accept_result = tcp_listener.accept().await;
                if let Err(e) = agent_connection_accept_result {
                    error!("Fail to accept agent protocol because of error: {:#?}", e);
                    continue;
                }
                let (agent_stream, agent_remote_addr) = agent_connection_accept_result.unwrap();
                if let Err(e) = agent_stream.set_nodelay(true) {
                    error!("Fail to set no delay on agent stream because of error, agent stream:{:?}, error: {:#?}", agent_stream, e);
                }
                let transport_info_sender = transport_info_sender.clone();
                let agent_public_key = agent_public_key.clone();
                let proxy_private_key = proxy_private_key.clone();
                worker_runtime.spawn(async move {
                    let tcp_transport = TcpTransport::new(agent_remote_addr,
                                                          transport_info_sender.clone());
                    if let Err(e) = tcp_transport {
                        error!("Fail to create agent tcp transport because of error, error: {:#?}",e );
                        return;
                    }
                    let mut tcp_transport = tcp_transport.unwrap();
                    let tcp_transport_id = tcp_transport.id().to_string();
                    info!("Receive a agent stream from: [{}], assign it to transport: [{}].", agent_remote_addr, tcp_transport_id);
                    if let Err(e) = tcp_transport.start(agent_stream, agent_public_key, proxy_private_key).await {
                        error!("Fail to start agent tcp transport because of error, transport:[{}], agent address:[{}], error: {:#?}",tcp_transport_id,
                            agent_remote_addr,e);
                    }
                    if let Err(e) = tcp_transport.close().await {
                        error!("Fail to close agent tcp transport because of error, transport:[{}], agent address:[{}], error: {:#?}",tcp_transport_id,
                            agent_remote_addr,e);
                    }
                    info!("Graceful close agent tcp transport: [{}]", tcp_transport_id);
                });
            }
        });
        Ok(())
    }

    pub fn shutdown(self) {
        self.master_runtime.shutdown_timeout(Duration::from_secs(20));
        info!("Graceful shutdown ppaass server.")
    }
}