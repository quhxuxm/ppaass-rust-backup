#![cfg(test)]

mod test {
    use uuid::Uuid;

    use common::common::PpaassMessage;
    use common::error::PpaassError;

    #[test]
    fn test_ppaass_message_to_bytes() -> Result<(), PpaassError> {
        let random_data = Uuid::new_v4().as_bytes().to_vec();
        let payload_encryption_token = random_data.clone();
        let encrypted_payload = random_data.clone();
        let ppaass_message = PpaassMessage::new_with_random_encryption_type(
            payload_encryption_token, encrypted_payload);
        let message_as_bytes: Vec<u8> = ppaass_message.into();
        let original_ppaass_message_bytes = message_as_bytes.clone();
        let parsed_ppaass_message: PpaassMessage = message_as_bytes.try_into()?;
        println!("{:#?}", original_ppaass_message_bytes);
        assert_eq!(parsed_ppaass_message.encrypted_payload, random_data);
        assert_eq!(parsed_ppaass_message.payload_encryption_token, random_data);
        println!("{:#?}", Uuid::from_slice(parsed_ppaass_message.id.as_slice()));
        println!("{:#?}", Uuid::from_slice(parsed_ppaass_message.payload_encryption_token.as_slice()));
        println!("{:#?}", Uuid::from_slice(parsed_ppaass_message.encrypted_payload.as_slice()));
        Ok(())
    }
}
