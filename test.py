import sys
import ssl
import ssl_psk
import socket

psk = 'c033f52671c61c8128f7f8a40be88038bcf2b07a6eb3095c36e3759f0cf40837'.decode('hex')
addr = ('localhost', 6000)
srv = bool(sys.argv[1:] and sys.argv[1] == '--server')

s = socket.socket()

if srv:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(addr)
    s.listen(1)
    s, _ = s.accept()
else:
    s.connect(addr)

sock = ssl_psk.wrap_socket(s, psk=psk, ciphers='PSK-AES256-CBC-SHA',
                           ssl_version=ssl.PROTOCOL_TLSv1,
                           server_side=srv,)

if srv:
    data = sock.recv(10)
    sock.sendall(data.upper())
else:
    sock.sendall('abcdefghi\n')
    print sock.recv(10)

sock.shutdown(socket.SHUT_RDWR)
s.close()
