use bytes::{BufMut, BytesMut};

use crate::prelude::*;

/// The agent message body type
pub enum PpaassAgentMessageBodyType {
    TcpConnect,
    TcpData,
    UdpAssociate,
    UdpData,
}

impl From<PpaassAgentMessageBodyType> for u8 {
    fn from(value: PpaassAgentMessageBodyType) -> Self {
        match value {
            PpaassAgentMessageBodyType::TcpConnect => 1,
            PpaassAgentMessageBodyType::TcpData => 2,
            PpaassAgentMessageBodyType::UdpAssociate => 3,
            PpaassAgentMessageBodyType::UdpData => 4,
        }
    }
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

impl From<PpaassAgentMessageBody> for Vec<u8> {
    fn from(value: PpaassAgentMessageBody) -> Self {
        let mut result = BytesMut::new();
        result.put_u8(value.body_type.into());
        let user_token_length = value.user_token.len();
        result.put_u64(user_token_length as u64);
        result.put_slice(value.user_token.as_bytes());
        let source_address: Vec<u8> = value.source_address.into();
        result.put_slice(source_address.as_slice());
        let target_address: Vec<u8> = value.target_address.into();
        result.put_slice(target_address.as_slice());
        result.put_u64(value.data.len() as u64);
        result.put_slice(value.data.as_slice());
        result.to_vec()
    }
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

impl From<PpaassAgentMessage> for Vec<u8> {
    fn from(value: PpaassAgentMessage) -> Self {
        let mut result = BytesMut::new();
        let id_length = value.id.len();
        result.put_u64(id_length as u64);
        result.put_slice(value.id.as_bytes());
        let encryption_token_length = value.encryption_token.len();
        result.put_u64(encryption_token_length as u64);
        result.put_slice(value.encryption_token.as_bytes());
        result.put_u8(value.body_encryption_type.into());
        let body_bytes: Vec<u8> = value.body.into();
        result.put_slice(body_bytes.as_slice());
        result.to_vec()
    }
}