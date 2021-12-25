use std::error::Error;

use ppaass_common::agent::PpaassAgentMessagePayloadType;
use ppaass_common::common::PpaassAddress;
use ppaass_common::error::PpaassCommonError;

use crate::transport::TcpTransportStatus;

#[derive(thiserror::Error, Debug)]
pub(crate) enum PpaassProxyError {
    #[error("Connect to target fail")]
    ConnectToTargetFail(#[from] std::io::Error),
    #[error("Invalid tcp transport status, Transport: [{0}] require status: {1:#?}, get status: {2:#?}")]
    InvalidTcpTransportStatus(String, TcpTransportStatus, TcpTransportStatus),
    #[error("Receive invalid agent message, Transport: [{0}] require status: {1:#?}, get status: {2:#?}")]
    ReceiveInvalidAgentMessage(String, PpaassAgentMessagePayloadType, PpaassAgentMessagePayloadType),
}

