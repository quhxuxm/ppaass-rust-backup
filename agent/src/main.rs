use anyhow::Result;
use log::{error, info};

use agent::server::Server;

fn main() -> Result<()> {
    let server = Server::new()?;
    match server.run() {
        Err(e) => {
            error!("Server fail to start because of error: {:#?}", e);
        }
        Ok(_) => {
            info!("Server graceful shutdown");
        }
    };
    server.shutdown();
    Ok(())
}

