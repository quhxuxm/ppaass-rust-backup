import socket

import socks

if __name__ == "__main__":
    sock = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.set_proxy(socks.SOCKS5, "10.175.4.220", 10081)
    # sock.bind(("0.0.0.0", 8701))
    sock.connect(("10.175.4.220", 8700))
    print('Start client: [%s]', sock)
    i = 0
    while True:
        message = bytes('This is client message.  It will be repeated: %s' % i, 'utf-8')
        i = i + 1
        print('sending [%s]' % message)
        sock.send(message)
        data = sock.recv(65535)
        print('received [%s]' % data)

    sock.close()
