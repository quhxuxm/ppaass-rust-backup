use std::error::Error;
use std::string::FromUtf8Error;

#[derive(thiserror::Error, Debug)]
pub enum PpaassCommonError {
    #[error("Fail to parse ppaass ip v4 address")]
    FailToParsePpaassIpv4Address,
    #[error("Fail to parse ppaass ip v6 address")]
    FailToParsePpaassIpv6Address,
    #[error("Fail to parse ppaass domain address")]
    FailToParsePpaassDomainAddress,
    #[error("Fail to parse ppaass address type: {0}")]
    FailToParsePpaassAddressType(u8),
    #[error("Fail to parse ppaass address from string: {0}")]
    FailToParsePpaassAddressFromString(String),
    #[error("Fail to parse ppaass message payload encryption type: {0}")]
    FailToParsePpaassMessagePayloadEncryptionType(u8),
    #[error("Fail to parse ppaass agent message payload type: {0}")]
    FailToParsePpaassAgentMessagePayloadType(u8),
    #[error("Fail to parse ppaass proxy message payload type: {0}")]
    FailToParsePpaassProxyMessagePayloadType(u8),
    #[error("Fail to parse utf8 string: {0:#?}")]
    FailToParseUtf8String(#[from]FromUtf8Error),
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
        #[from] source: std::io::Error
    },
}
