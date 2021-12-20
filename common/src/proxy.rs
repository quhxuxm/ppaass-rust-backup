use crate::prelude::*;

/// The proxy message body type
pub enum PpaassProxyMessageBodyType {
    TcpConnectSuccess,
    TcpConnectFail,
    TcpDataSuccess,
    TcpDataFail,
    UdpAssociateSuccess,
    UdpAssociateFail,
    UdpDataSuccess,
    UdpDataFail,
}

/// The proxy message body
pub struct PpaassProxyMessageBody {
    /// The user token
    pub user_token: String,
    /// The source address
    pub source_address: PpaassAddress,
    /// The target address
    pub target_address: PpaassAddress,
    /// The body type
    pub body_type: PpaassProxyMessageBodyType,
    /// The data
    pub data: Vec<u8>,
}

/// The proxy message
pub struct PpaassProxyMessage {
    /// The message id
    pub id: String,
    /// The encryption token
    pub encryption_token: String,
    /// The body encryption type
    pub body_encryption_type: PpaassMessageBodyEncryptionType,
    /// The message body
    pub body: PpaassProxyMessageBody,
}