use std::net::UdpSocket;
use anyhow::Result;

fn main() -> Result<()>{
    println!("Begin udp client testing");
    let udp_client = UdpSocket::bind("10.175.4.220:8800")?;
    udp_client.connect("10.175.4.220:8801")?;
    let mut index = 0;
    loop {
        println!("Begin a client loop: {}", index);
        udp_client.send(format!("Client message : {}", index).as_bytes())?;
        let mut server_response_buf = [0u8; 65536];
      let (size, server_address)=  udp_client.recv_from(&mut server_response_buf)?;
        let server_response_buf = &mut server_response_buf[..size];
        println!(
            "Receive from server: {}, message:{}",
            server_address,
            String::from_utf8(server_response_buf.to_vec())
                .unwrap_or_else(|e| { format!("{:#?}", e) })
        );
        index += 1;
    }
}
