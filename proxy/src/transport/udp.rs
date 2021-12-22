use tokio::net::UdpSocket;

pub(crate) struct UdpTransport {
    id: Vec<u8>,
    read_bytes: u64,
    write_bytes: u64,
    start_time: u64,
    end_time: u64,
    user_token: Vec<u8>,
    udp_socket: UdpSocket,
}
