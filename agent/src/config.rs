use lazy_static::lazy_static;
use serde_derive::Deserialize;
use serde_derive::Serialize;
use std::path::Path;

pub const DEFAULT_TCP_BUFFER_SIZE: usize = 128 * 1024;
pub const DEFAULT_TCP_MAX_FRAME_SIZE: usize = DEFAULT_TCP_BUFFER_SIZE * 2;
pub const DEFAULT_UDP_BUFFER_SIZE: usize = 65536;

lazy_static! {
    pub(crate) static ref AGENT_SERVER_CONFIG: AgentConfiguration = {
        let config_file_content = std::fs::read_to_string("ppaass-agent.toml")
            .expect("Fail to read agent configuration file.");
        toml::from_str::<AgentConfiguration>(&config_file_content)
            .expect("Fail to parse agent configuration file")
    };
    pub(crate) static ref AGENT_PRIVATE_KEY: String =
        std::fs::read_to_string(Path::new("AgentPrivateKey.pem"))
            .expect("Fail to read agent private key.");

    pub(crate) static ref PROXY_PUBLIC_KEY: String =
        std::fs::read_to_string(Path::new("ProxyPublicKey.pem"))
            .expect("Fail to read proxy public key.");
}
#[derive(Serialize, Deserialize, Debug)]
pub struct AgentConfiguration {
    port: Option<u16>,
    user_token: Option<String>,
    proxy_addresses: Option<Vec<String>>,
    proxy_port: Option<u16>,
    buffer_size: Option<usize>,
    max_frame_size: Option<usize>,
    thread_number: Option<usize>,
    max_blocking_threads: Option<usize>,
    thread_timeout: Option<u64>,
    proxy_connect_timeout: Option<u64>,
    proxy_connection_max_idle: Option<u64>,
    client_connection_max_idle: Option<u64>,
    log_config: Option<String>,
    compress: Option<bool>,
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
    pub fn max_frame_size(&self) -> Option<usize> {
        self.max_frame_size
    }
    pub fn thread_number(&self) -> Option<usize> {
        self.thread_number
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
    pub fn compress(&self) -> Option<bool> {
        self.compress
    }
}
