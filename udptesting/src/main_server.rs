use std::net::UdpSocket;

use anyhow::Result;

fn main() -> Result<()> {
    println!("Begin udp server testing");
    let udp_server = UdpSocket::bind("0.0.0.0:8801")?;
    let mut index = 0;
    loop {
        println!("Begin a server loop: {}", index);
        let mut client_message_buf = [0u8; 65536];
        let (size, client_address) = udp_server.recv_from(&mut client_message_buf)?;
        let client_message_buf = &mut client_message_buf[..size];
        println!(
            "Receive from client: {}, message: {}",
            client_address,
            String::from_utf8(client_message_buf.to_vec())
                .unwrap_or_else(|e| { format!("{:#?}", e) })
        );
        udp_server.send_to(format!("Server echo: {}", index).as_bytes(), client_address)?;
        index += 1;
    }
}
