import socket

if __name__ == "__main__":
    server_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_udp_socket.bind(("0.0.0.0", 8888))
    print('Start listening udp:', server_udp_socket)
    i = 0
    while True:
        message, client_address = server_udp_socket.recvfrom(65535)
        print('client udp socket from: ', client_address)
        print('server receive udp message: [%s]' % message)
        print('server send udp data back to the client [%s]' % i)
        # sock.send(bytes("server echo: [%s]" % i, "utf-8"))
        server_udp_socket.sendto(bytes("server echo %s" % i, "utf-8"), client_address)
        print('server finish udp echo [%s]' % i)
        i = i + 1
