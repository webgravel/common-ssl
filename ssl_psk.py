import ssl
import _ssl_psk

# memory leak!
_sslptr_to_psk = {}

def _psk_callback(ssl):
    return _sslptr_to_psk[ssl]

_ssl_psk.set_python_psk_callback(_psk_callback)

def set_client_psk(ssl, psk):
    ptr = _ssl_psk.set_psk_callback(ssl._sslobj)
    _sslptr_to_psk[ptr] = psk

def set_server_psk(ssl, psk):
    ptr = _ssl_psk.set_psk_server_callback(ssl._sslobj)
    _sslptr_to_psk[ptr] = psk

def wrap_socket(*args, **kwargs):
    psk = kwargs.setdefault('psk', None)
    del kwargs['psk']
    do_handshake_on_connect = kwargs.get('do_handshake_on_connect', True)
    kwargs['do_handshake_on_connect'] = False

    kwargs.setdefault('server_side', False)
    server_side = kwargs['server_side']
    if psk:
        del kwargs['server_side'] # bypass need for cert

    sock = ssl.wrap_socket(*args, **kwargs)
    if psk:
        if server_side:
            set_server_psk(sock, psk)
        else:
            set_client_psk(sock, psk)
    if do_handshake_on_connect:
        sock.do_handshake()
    return sock
