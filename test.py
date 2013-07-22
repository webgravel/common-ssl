import ssl
import ssl_psk
import socket

s = socket.socket()
s.connect(('localhost', 6000))
sock = ssl.wrap_socket(s, do_handshake_on_connect=False)
ssl_psk.set_psk(sock, 'c033f52671c61c8128f7f8a40be88038bcf2b07a6eb3095c36e3759f0cf40837'.decode('hex'))
sock.do_handshake()

sock.sendall('hello!\n')
sock.shutdown(socket.SHUT_RDWR)
s.close()
