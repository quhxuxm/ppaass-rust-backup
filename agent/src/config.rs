use serde_derive::Deserialize;
use serde_derive::Serialize;

#[derive(Serialize, Deserialize, Debug)]
pub struct AgentConfiguration {
    port: Option<u16>,
    user_token: Option<String>,
    proxy_addresses: Option<Vec<String>>,
    proxy_port: Option<u16>,
    buffer_size: Option<usize>,
    master_thread_number: Option<usize>,
    worker_thread_number: Option<usize>,
    max_blocking_threads: Option<usize>,
    thread_timeout: Option<u64>,
    proxy_connect_timeout: Option<u64>,
    proxy_connection_max_idle: Option<u64>,
    client_connection_max_idle: Option<u64>,
    log_config: Option<String>,
}

impl AgentConfiguration {
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    pub fn user_token(&self) -> &Option<String> {
        &self.user_token
    }

    pub fn proxy_addresses(&self) -> &Option<Vec<String>> {
        &self.proxy_addresses
    }

    pub fn proxy_port(&self) -> Option<u16> {
        self.proxy_port
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

    pub fn max_blocking_threads(&self) -> Option<usize> {
        self.max_blocking_threads
    }

    pub fn thread_timeout(&self) -> Option<u64> {
        self.thread_timeout
    }

    pub fn proxy_connect_timeout(&self) -> Option<u64> {
        self.proxy_connect_timeout
    }

    pub fn log_config(&self) -> &Option<String> {
        &self.log_config
    }

    pub fn proxy_connection_max_idle(&self) -> Option<u64> {
        self.proxy_connection_max_idle
    }

    pub fn client_connection_max_idle(&self) -> Option<u64> {
        self.client_connection_max_idle
    }
}
