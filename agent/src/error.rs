use crate::transport::common::TransportStatus;

#[derive(thiserror::Error, Debug)]
pub(crate) enum PpaassAgentError {
    #[error("Fail to connect proxy")]
    FailToConnectProxy,
    #[error("Fail to associate udp on proxy")]
    FailToAssociateUdpOnProxy,
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
    #[error("Invalid transport status, transport: [{0}], require: {1:?}, given: {2:?}")]
    InvalidTransportStatus(String, TransportStatus, TransportStatus),
    #[error("Io error happen")]
    IoError(#[from] std::io::Error),
    #[error("Unsupported socks 5 command")]
    UnsupportedSocks5Command,
}
