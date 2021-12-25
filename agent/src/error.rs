#[derive(thiserror::Error, Debug)]
pub(crate) enum PpaassAgentError {
    #[error("Connect to target fail")]
    ConnectToProxyFail(#[from] std::io::Error),
    #[error("Fail to codec http protocol")]
    HttpCodecError(#[from] bytecodec::Error),
}