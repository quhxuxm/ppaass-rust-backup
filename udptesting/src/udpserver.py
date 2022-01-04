import socket

if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 8700))
    print('Start listening udp: [%s]', sock)
    i = 0
    while True:
        message, client_address = sock.recvfrom(65535)
        print('connection from', client_address)
        print('received "%s"' % message)
        print('sending data back to the client [%s]' % i)
        # sock.send(bytes("server echo: [%s]" % i, "utf-8"))
        sock.sendto(bytes("server echo: [%s]" % i, "utf-8"), client_address)
        print('finish', client_address)
        i = i + 1
