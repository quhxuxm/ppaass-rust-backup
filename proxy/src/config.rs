use serde_derive::Deserialize;
use serde_derive::Serialize;

#[derive(Serialize, Deserialize, Debug)]
pub struct ProxyConfiguration {
    port: Option<u16>,
    buffer_size: Option<usize>,
    master_thread_number: Option<usize>,
    worker_thread_number: Option<usize>,
    max_blocking_threads: Option<usize>,
    thread_timeout: Option<u64>,
    target_connect_timeout: Option<u64>,
    agent_connection_max_idle: Option<u64>,
    target_connection_max_idle: Option<u64>,
    log_config: Option<String>,
}

impl ProxyConfiguration {
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    pub fn buffer_size(&self) -> Option<usize> {
        self.buffer_size
    }
    pub fn master_thread_number(&self) -> Option<usize> {
        self.master_thread_number
    }
    pub fn worker_thread_number(&self) -> Option<usize> {
        self.worker_thread_number
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
}
