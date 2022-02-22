use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use log::{error, info};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

use crate::config::PROXY_SERVER_CONFIG;
use crate::transport::Transport;

const LOCAL_ADDRESS: [u8; 4] = [0u8; 4];

pub struct Server {
    runtime: Runtime,
}

impl Server {
    pub fn new() -> Result<Self> {
        log4rs::init_file(
            PROXY_SERVER_CONFIG.log_config().as_ref().unwrap(),
            Default::default(),
        )
        .with_context(|| "Fail to initialize proxy configuration file.")?;
        let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
        runtime_builder.worker_threads(
            PROXY_SERVER_CONFIG
                .thread_number()
                .with_context(|| "Can not get worker threads number from proxy configuration.")?,
        );
        runtime_builder.max_blocking_threads(
            PROXY_SERVER_CONFIG
                .max_blocking_threads()
                .with_context(|| {
                    "Can not get max blocking threads number from proxy configuration."
                })?,
        );
        runtime_builder.thread_name("proxy-master");
        runtime_builder.thread_keep_alive(Duration::from_secs(
            PROXY_SERVER_CONFIG
                .thread_timeout()
                .with_context(|| "Can not get thread timeout from proxy configuration.")?,
        ));
        runtime_builder.enable_all();
        let runtime = runtime_builder
            .build()
            .with_context(|| "Fail to build init tokio runtime.")?;
        Ok(Self { runtime })
    }

    pub fn run(&self) -> Result<()> {
        self.runtime.block_on(async move {
            let local_port = PROXY_SERVER_CONFIG.port().unwrap();
            let local_ip = IpAddr::from(LOCAL_ADDRESS);
            let local_address = SocketAddr::new(local_ip, local_port);
            let tcp_listener = TcpListener::bind(local_address).await.unwrap_or_else(|e| panic!("Fail to start proxy because of error, error: {:#?}", e));
            //Start to processing client protocol
            info!("Success to bind TCP server on port: [{}]", local_port);

            loop {
                let (agent_stream, agent_remote_address)  =match  tcp_listener.accept().await{
                    Err(e)=>{
                        error!("Fail to accept agent protocol because of error: {:#?}", e);
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
                    let mut transport = match Transport::new(agent_remote_address){
                        Err(e)=>{
                            error!("Fail to create agent tcp transport because of error, error: {:#?}",e );
                            return;
                        }
                        Ok(r)=>r
                    };
                    let transport_id = transport.id().to_string();
                    info!("Receive a agent stream from: [{}], assign it to transport: [{}].", agent_remote_address, transport_id);
                    if let Err(e) = transport.start(agent_stream).await {
                        error!("Fail to start agent tcp transport because of error, transport:[{}], agent address:[{}], error: {:#?}",transport_id,
                            agent_remote_address,e);
                    }
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
