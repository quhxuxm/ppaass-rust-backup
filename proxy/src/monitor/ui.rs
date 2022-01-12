use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::routing::get;
use axum::Router;

use crate::config::ProxyConfiguration;

pub(crate) struct MonitorUi {
    configuration: Arc<ProxyConfiguration>,
}

impl MonitorUi {
    pub(crate) fn new(configuration: Arc<ProxyConfiguration>) -> Self {
        Self { configuration }
    }

    pub(crate) async fn start(&self) -> Result<()> {
        let app = Router::new().route("/", get(|| async { "Hello world" }));
        let server_address =
            &SocketAddr::from(([0, 0, 0, 0], self.configuration.monitor_port().unwrap()));
        axum::Server::bind(server_address)
            .serve(app.into_make_service())
            .await?;
        Ok(())
    }
}
