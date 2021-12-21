use std::error::Error;

#[derive(thiserror::Error, Debug)]
pub enum PpaassError {
    #[error("Fail to parse ppaass ip v4 address")]
    FailToParsePpaassIpv4Address,
    #[error("Fail to parse ppaass ip v6 address")]
    FailToParsePpaassIpv6Address,
    #[error("Fail to parse ppaass domain address")]
    FailToParsePpaassDomainAddress,
    #[error("Fail to parse ppaass address type: {0}")]
    FailToParsePpaassAddressType(u8),
    #[error("Fail to parse ppaass message payload encryption type: {0}")]
    FailToParsePpaassMessagePayloadEncryptionType(u8),
    #[error("Fail to parse ppaass agent message payload type: {0}")]
    FailToParsePpaassAgentMessagePayloadType(u8),
    #[error("Fail to parse ppaass proxy message payload type: {0}")]
    FailToParsePpaassProxyMessagePayloadType(u8),
    #[error("Fail to parse rsa key")]
    FailToParseRsaKey {
        source: rsa::pkcs8::Error,
    },
    #[error("Fail to encrypt data with rsa")]
    FailToEncryptDataWithRsa {
        source: rsa::errors::Error
    },
    #[error("I/O error happen")]
    IoError {
        source: std::io::Error
    },
    #[error("A unknown ppaass error happen.")]
    Other {
        source: Box<dyn Error>
    },
}