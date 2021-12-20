#[derive(thiserror::Error, Debug)]
pub enum PpaassError {
    #[error("Fail to parse ppaass ip v4 address")]
    FailToParsePpaassIpv4Address,
    #[error("Fail to parse ppaass ip v6 address")]
    FailToParsePpaassIpv6Address,
    #[error("Fail to parse ppaass domain address")]
    FailToParsePpaassDomainAddress,
    #[error("Fail to parse ppaass address type")]
    FailToParsePpaassAddressType,
    #[error("A unknown ppaass error happen.")]
    Other
}