use crate::prelude::*;

/// The agent message body type
pub enum PpaassAgentMessageBodyType {
    TcpConnect,
    TcpData,
    UdpAssociate,
    UdpData,
}

/// The agent message body
pub struct PpaassAgentMessageBody {
    /// The user token
    pub user_token: String,
    /// The source address
    pub source_address: PpaassAddress,
    /// The target address
    pub target_address: PpaassAddress,
    /// The body type
    pub body_type: PpaassAgentMessageBodyType,
    /// The data
    pub data: Vec<u8>,
}

/// The agent message
pub struct PpaassAgentMessage {
    /// The message id
    pub id: String,
    /// The encryption token
    pub encryption_token: String,
    /// The body encryption type
    pub body_encryption_type: PpaassMessageBodyEncryptionType,
    /// The message body
    pub body: PpaassAgentMessageBody,
}