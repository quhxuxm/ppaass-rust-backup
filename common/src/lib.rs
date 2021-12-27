use uuid::Uuid;

pub mod agent;
pub mod proxy;
pub mod error;
pub mod common;
pub mod codec;
pub(crate) mod crypto;

pub fn generate_uuid() -> String {
    let uuid = Uuid::new_v4().to_string();
    uuid.replace('-', "")
}
