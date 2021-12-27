use crate::error::PpaassAgentError;

pub(crate) struct ProxyAddress {
    host: String,
    port: u16,
}

impl TryFrom<String> for ProxyAddress {
    type Error = PpaassAgentError;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        let trimmed_proxy_address = value.trim();
        let proxy_address_parts: Vec<&str> = trimmed_proxy_address.split(":").collect();
        if proxy_address_parts.len() != 2 {
            return Err(PpaassAgentError::FailToParseProxyAddress(value));
        }
        let host = proxy_address_parts[0].to_string();
        let port = proxy_address_parts[1].parse::<u16>().map_err(|e| {
            PpaassAgentError::FailToParseProxyAddress(value)
        })?;
        Ok(Self {
            host,
            port,
        })
    }
}

impl From<ProxyAddress> for String {
    fn from(value: ProxyAddress) -> Self {
        format!("{}:{}", value.host, value.port)
    }
}
