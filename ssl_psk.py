import _ssl_psk

_sslptr_to_psk = {}

def _psk_callback(ssl):
    return _sslptr_to_psk[ssl]

_ssl_psk.set_python_psk_callback(_psk_callback)

def set_psk(ssl, psk):
    ptr = _ssl_psk.set_psk_callback(ssl._sslobj)
    _sslptr_to_psk[ptr] = psk
