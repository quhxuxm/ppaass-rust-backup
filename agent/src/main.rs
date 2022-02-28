use anyhow::Result;
use chrono::Local;
use tracing::{error, info};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;

use agent::config::AGENT_SERVER_CONFIG;
use agent::server::Server;

struct LogTimer;

impl FormatTime for LogTimer {
    fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
        write!(w, "{}", Local::now().format("%FT%T%.3f"))
    }
}

fn main() -> Result<()> {
    let file_appender = tracing_appender::rolling::hourly(
        AGENT_SERVER_CONFIG
            .log_dir()
            .as_ref()
            .expect("No log directory given."),
        AGENT_SERVER_CONFIG
            .log_file()
            .as_ref()
            .expect("No log file name given."),
    );
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    tracing_subscriber::fmt()
        .with_level(true)
        .with_target(true)
        .with_timer(LogTimer)
        .with_thread_ids(true)
        .with_file(true)
        .with_ansi(false)
        .with_line_number(true)
        .with_writer(non_blocking)
        .with_ansi(true)
        .init();
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
