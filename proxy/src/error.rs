use ppaass_common::agent::PpaassAgentMessagePayloadType;

use crate::transport::TransportStatus;

#[derive(thiserror::Error, Debug)]
pub(crate) enum PpaassProxyError {
    #[error("Connect to target fail")]
    ConnectToTargetFail(#[from] std::io::Error),
    #[error(
        "Invalid tcp transport status, Transport: [{0}] require status: {1:#?}, get status: {2:#?}"
    )]
    InvalidTcpTransportStatus(String, TransportStatus, TransportStatus),
    #[error(
        "Invalid udp transport status, Transport: [{0}] require status: {1:#?}, get status: {2:#?}"
    )]
    InvalidUdpTransportStatus(String, TransportStatus, TransportStatus),
    #[error("Receive invalid agent message, Transport: [{0}] require status: {1:#?}, get status: {2:#?}")]
    ReceiveInvalidAgentMessage(
        String,
        PpaassAgentMessagePayloadType,
        PpaassAgentMessagePayloadType,
    ),
    #[error("Unknown error happen")]
    UnknownError,
}
