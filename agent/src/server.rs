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

use crate::config::AgentConfiguration;
use crate::transport::common::{Transport, TransportSnapshot, TransportStatus};
use crate::transport::http::HttpTransport;
use crate::transport::socks::Socks5Transport;

const CONFIG_FILE_PATH: &str = "ppaass-agent.toml";
pub const LOCAL_ADDRESS: [u8; 4] = [0u8; 4];

const AGENT_PRIVATE_KEY_PATH: &str = "AgentPrivateKey.pem";
const PROXY_PUBLIC_KEY_PATH: &str = "ProxyPublicKey.pem";
const SOCKS5_VERSION: u8 = 5;
const SOCKS4_VERSION: u8 = 4;

pub struct Server {
    master_runtime: Runtime,
    worker_runtime: Arc<Runtime>,
    configuration: Arc<AgentConfiguration>,
}

impl Server {
    pub fn new() -> Result<Self> {
        let mut config_file = File::open(CONFIG_FILE_PATH)?;
        let mut config_file_content = String::new();
        config_file.read_to_string(&mut config_file_content)?;
        let config = toml::from_str::<AgentConfiguration>(&config_file_content)
            .with_context(|| "Fail to parse agent configuration file.")?;
        log4rs::init_file(config.log_config().as_ref().unwrap(), Default::default())
            .with_context(|| "Fail to initialize agent configuration file.")?;
        let mut master_runtime_builder = tokio::runtime::Builder::new_multi_thread();
        master_runtime_builder.worker_threads(
            config
                .master_thread_number()
                .with_context(|| "Can not get worker threads number from agent configuration.")?,
        );
        master_runtime_builder.max_blocking_threads(config.max_blocking_threads().with_context(
            || "Can not get max blocking threads number from agent configuration.",
        )?);
        master_runtime_builder.thread_name("agent-master");
        master_runtime_builder.thread_keep_alive(Duration::from_secs(
            config
                .thread_timeout()
                .with_context(|| "Can not get thread timeout from agent configuration.")?,
        ));
        master_runtime_builder.enable_all();
        let master_runtime = master_runtime_builder
            .build()
            .with_context(|| "Fail to build init tokio runtime.")?;
        let mut worker_runtime_builder = tokio::runtime::Builder::new_multi_thread();
        worker_runtime_builder.worker_threads(
            config
                .worker_thread_number()
                .with_context(|| "Can not get relay thread number from agent configuration.")?,
        );
        worker_runtime_builder.max_blocking_threads(config.max_blocking_threads().with_context(
            || "Can not get max blocking threads number from agent configuration.",
        )?);
        worker_runtime_builder.thread_name("agent-worker");
        worker_runtime_builder.thread_keep_alive(Duration::from_secs(
            config
                .thread_timeout()
                .with_context(|| "Can not get thread time out from agent configuration.")?,
        ));
        worker_runtime_builder.enable_all();
        let worker_runtime = worker_runtime_builder.build()?;
        Ok(Self {
            master_runtime,
            worker_runtime: Arc::new(worker_runtime),
            configuration: Arc::new(config),
        })
    }

    pub fn run(&self) -> Result<()> {
        let agent_private_key = std::fs::read_to_string(Path::new(AGENT_PRIVATE_KEY_PATH))
            .expect("Fail to read agent private key.");
        let proxy_public_key = std::fs::read_to_string(Path::new(PROXY_PUBLIC_KEY_PATH))
            .expect("Fail to read proxy public key.");
        let config = self.configuration.clone();
        let worker_runtime = self.worker_runtime.clone();
        let (transport_info_sender, mut transport_info_receiver) =
            tokio::sync::mpsc::channel::<TransportSnapshot>(32);
        self.master_runtime.spawn(async move {
            loop {
                let transport_snapshot = transport_info_receiver.recv().await;
                match transport_snapshot {
                    None => {
                        continue;
                    }
                    Some(snapshot) => {
                        if snapshot.status == TransportStatus::Closed {
                            info!("Remove closed transport, transport: [{}]", snapshot.id);
                            continue;
                        }
                        info!("Update transport, transport: [{}]", snapshot.id);
                    }
                }
            }
        });
        self.master_runtime.block_on(async move {
            let local_port = config.port().unwrap();
            let local_ip = IpAddr::from(LOCAL_ADDRESS);
            let local_address = SocketAddr::new(local_ip, local_port);
            let tcp_listener = TcpListener::bind(local_address).await.unwrap_or_else(|e| panic!("Fail to start agent because of error, error: {:#?}", e));
            //Start to processing client protocol
            info!("Success to bind TCP server on port: [{}]", local_port);
            loop {
                let (client_stream, client_remote_addr) = match tcp_listener.accept().await{
                    Err(e)=>{
                        error!("Fail to accept client protocol because of error: {:#?}", e);
                        continue;
                    }
                    Ok(r)=>{
                        if let Err(e) = r.0.set_nodelay(true) {
                            error!("Fail to set no delay on agent stream because of error, agent stream:{:?}, error: {:#?}", r.0, e);
                        }
                        r
                    }
                };
                let transport_info_sender = transport_info_sender.clone();
                let agent_private_key = agent_private_key.clone();
                let proxy_public_key = proxy_public_key.clone();
                let config = config.clone();
                worker_runtime.spawn(async move {
                    let mut protocol_buf: [u8; 1] = [0; 1];
                    let read_result = client_stream.peek(&mut protocol_buf).await;
                    if let Err(e) = read_result {
                        error!("Fail to read data from client: {}", client_remote_addr);
                        return;
                    }
                    if let Ok(0) = read_result {
                        info!("No remaining data from client: {}", client_remote_addr);
                        return;
                    }
                    if protocol_buf[0] == SOCKS4_VERSION {
                        error!("Do not support socks 4 connection, client: {}", client_remote_addr);
                        return;
                    }
                    if protocol_buf[0] == SOCKS5_VERSION {
                        let mut socks5_transport = match Socks5Transport::new(config.clone(), transport_info_sender.clone()){
                            Err(e)=>{
                                error!("Fail to create socks5 transport because of error, error: {:#?}",e );
                                return;
                            }
                            Ok(r)=>r
                        };
                        let socks5_transport_id = socks5_transport.id();
                        info!("Receive a client stream from: [{}], assign it to socks5 transport: [{}].", client_remote_addr, socks5_transport_id);
                        if let Err(e) = socks5_transport.start(client_stream, proxy_public_key, agent_private_key).await {
                            error!("Fail to start agent socks5 transport because of error, transport:[{}], agent address:[{}], error: {:#?}",socks5_transport_id,
                            client_remote_addr,e);
                        }
                        if let Err(e) = socks5_transport.close().await {
                            error!("Fail to close agent socks5 transport because of error, transport:[{}], agent address:[{}], error: {:#?}",socks5_transport_id,
                            client_remote_addr,e);
                        }
                        info!("Graceful close agent socks5 transport: [{}]", socks5_transport_id);
                        return;
                    }
                    let mut http_transport = match HttpTransport::new(config.clone(), transport_info_sender.clone()){
                        Err(e)=>{
                            error!("Fail to create agent http transport because of error, error: {:#?}",e );
                            return;
                        }
                        Ok(r)=>r
                    };
                    let http_transport_id = http_transport.id();
                    info!("Receive a client stream from: [{}], assign it to http transport: [{}].", client_remote_addr, http_transport_id);
                    if let Err(e) = http_transport.start(client_stream, proxy_public_key, agent_private_key).await {
                        error!("Fail to start agent http transport because of error, transport:[{}], agent address:[{}], error: {:#?}",http_transport_id,
                            client_remote_addr,e);
                    }
                    if let Err(e) = http_transport.close().await {
                        error!("Fail to close agent http transport because of error, transport:[{}], agent address:[{}], error: {:#?}",http_transport_id,
                            client_remote_addr,e);
                    }
                    info!("Graceful close agent http transport: [{}]", http_transport_id);
                });
            }
        });
        Ok(())
    }

    pub fn shutdown(self) {
        self.master_runtime
            .shutdown_timeout(Duration::from_secs(20));
        info!("Graceful shutdown ppaass server.")
    }
}
