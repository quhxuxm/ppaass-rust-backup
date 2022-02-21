use serde_derive::Deserialize;
use serde_derive::Serialize;

pub const DEFAULT_TCP_BUFFER_SIZE: usize = 128 * 1024;
pub const DEFAULT_TCP_MAX_FRAME_SIZE: usize = DEFAULT_TCP_BUFFER_SIZE * 2;
pub const DEFAULT_UDP_BUFFER_SIZE: usize = 65536;

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ProxyConfiguration {
    port: Option<u16>,
    buffer_size: Option<usize>,
    max_frame_size: Option<usize>,
    thread_number: Option<usize>,
    max_blocking_threads: Option<usize>,
    thread_timeout: Option<u64>,
    target_connect_timeout: Option<u64>,
    agent_connection_max_idle: Option<u64>,
    target_connection_max_idle: Option<u64>,
    log_config: Option<String>,
    compress: Option<bool>,
}

impl ProxyConfiguration {
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    pub fn buffer_size(&self) -> Option<usize> {
        self.buffer_size
    }

    pub fn max_frame_size(&self) -> Option<usize> {
        self.max_frame_size
    }

    pub fn thread_number(&self) -> Option<usize> {
        self.thread_number
    }

    pub fn thread_timeout(&self) -> Option<u64> {
        self.thread_timeout
    }

    pub fn target_connect_timeout(&self) -> Option<u64> {
        self.target_connect_timeout
    }

    pub fn log_config(&self) -> &Option<String> {
        &self.log_config
    }

    pub fn max_blocking_threads(&self) -> Option<usize> {
        self.max_blocking_threads
    }

    pub fn agent_connection_max_idle(&self) -> Option<u64> {
        self.agent_connection_max_idle
    }

    pub fn target_connection_max_idle(&self) -> Option<u64> {
        self.target_connection_max_idle
    }

    pub fn compress(&self) -> Option<bool> {
        self.compress
    }
}
