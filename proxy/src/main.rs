use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
use log::{debug, error, info};
use tokio::net::TcpListener;

use proxy::config::ProxyConfiguration;
use proxy::server::Server;
use proxy::transport::TcpTransport;

fn main() -> Result<()> {
    let server = Server::new()?;
    match server.run() {
        Err(e) => {
            error!("Server fail to start because of error: {:#?}", e);
            server.shutdown();
        }
        Ok(_) => {
            info!("Server graceful shutdown");
            server.shutdown();
        }
    };
    Ok(())
}
