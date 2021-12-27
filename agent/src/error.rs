#[derive(thiserror::Error, Debug)]
pub(crate) enum PpaassAgentError {
    #[error("Connect to target fail")]
    ConnectToProxyFail,
    #[error("Fail to codec http protocol")]
    HttpCodecError(#[from] bytecodec::Error),
    #[error("Fail to parse proxy address: {0}")]
    FailToParseProxyAddress(String),
    #[error("Fail to parse target host from http request")]
    FailToParseTargetHostFromHttpRequest,
    #[error("Fail to parse socks 5 connect request type: {0}")]
    FailToParseSocks5ConnectRequestType(u8),
    #[error("Fail to parse socks 5 address type: {0}")]
    FailToParseSocks5AddrType(u8),
    #[error("Fail to decode socks5 protocol")]
    FailToDecodeSocks5Protocol,

    #[error("Io error happen")]
    IoError(#[from] std::io::Error),
}
