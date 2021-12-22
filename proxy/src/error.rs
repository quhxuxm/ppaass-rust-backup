use std::error::Error;

use crate::transport::TcpTransportStatus;

#[derive(thiserror::Error, Debug)]
pub(crate) enum PpaassProxyError {
    #[error("Invalid tcp transport status, Transport: [{0}] require status: {1:#?}, get status: {2:#?}")]
    InvalidTcpTransportStatus(String, TcpTransportStatus, TcpTransportStatus),
    #[error("Other error")]
    Other {
        #[from] source: anyhow::Error
    },
}
