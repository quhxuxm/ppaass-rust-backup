use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{error, info};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

use crate::config::AGENT_SERVER_CONFIG;
use crate::transport::common::{Transport, TransportMetaInfo};
use crate::transport::http::HttpTransport;
use crate::transport::socks::Socks5Transport;

pub const LOCAL_ADDRESS: [u8; 4] = [0u8; 4];

const SOCKS5_VERSION: u8 = 5;
const SOCKS4_VERSION: u8 = 4;

pub struct Server {
    runtime: Runtime,
}

impl Server {
    pub fn new() -> Result<Self> {
        let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
        runtime_builder.worker_threads(
            AGENT_SERVER_CONFIG
                .thread_number()
                .with_context(|| "Can not get worker threads number from agent configuration.")?,
        );
        runtime_builder.max_blocking_threads(
            AGENT_SERVER_CONFIG
                .max_blocking_threads()
                .with_context(|| {
                    "Can not get max blocking threads number from agent configuration."
                })?,
        );
        runtime_builder.thread_name("agent-master");
        runtime_builder.thread_keep_alive(Duration::from_secs(
            AGENT_SERVER_CONFIG
                .thread_timeout()
                .with_context(|| "Can not get thread timeout from agent configuration.")?,
        ));
        runtime_builder.enable_all();
        let runtime = runtime_builder
            .build()
            .with_context(|| "Fail to build init tokio runtime.")?;
        Ok(Self { runtime })
    }

    pub fn run(&self) -> Result<()> {
        self.runtime.block_on(async move {
            let local_port = AGENT_SERVER_CONFIG.port().unwrap();
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
                            error!("Fail to set no delay on agent stream because of error, agent stream:{:?}, error: {:#?}", r.0.peer_addr(), e);
                        }
                        r
                    }
                };
                tokio::spawn(async move {
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
                    let transport_meta_info=match  TransportMetaInfo::new(){
                        Err(e)=>{
                            error!("Fail to create socks5 transport because of error, error: {:#?}",e );
                            return;
                        }
                        Ok(r)=>r
                    };
                    if protocol_buf[0] == SOCKS5_VERSION {
                        let socks5_transport_id = transport_meta_info.id.clone();
                        let mut socks5_transport = Socks5Transport::new(transport_meta_info);
                        info!("Receive a client stream from: [{}], assign it to socks5 transport: [{}].", client_remote_addr, socks5_transport_id);
                        if let Err(e) = socks5_transport.start(client_stream.into()).await {
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
                    let http_transport_id = transport_meta_info.id.clone();
                    let mut http_transport = HttpTransport::new(transport_meta_info);
                    info!("Receive a client stream from: [{}], assign it to http transport: [{}].", client_remote_addr, http_transport_id);
                    if let Err(e) = http_transport.start(client_stream.into()).await {
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
        self.runtime.shutdown_timeout(Duration::from_secs(20));
        info!("Graceful shutdown ppaass server.")
    }
}
