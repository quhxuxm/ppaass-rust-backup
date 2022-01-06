import socket

import socks

if __name__ == "__main__":
    client_udp_socket = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
    client_udp_socket.set_proxy(socks.SOCKS5, "192.168.31.200", 10080)
    # client_udp_socket.set_proxy(socks.SOCKS5, "10.175.4.220", 10081)
    # client_udp_socket.bind(("0.0.0.0", 9999))
    # client_udp_socket.connect(("192.168.31.200", 8888))
    client_udp_socket.connect(("172.17.22.149", 8888))
    print('Start udp client: ', client_udp_socket)
    i = 0
    while True:
        message = bytes('This is client message.  It will be repeated: %s' % i, 'utf-8')
        i = i + 1
        print('client sending udp message: [%s]' % message)
        client_udp_socket.send(message)
        data, server_address = client_udp_socket.recvfrom(65535)
        print('client receive udp message from server:', server_address)
        print('client receive udp message: [%s]' % data)
