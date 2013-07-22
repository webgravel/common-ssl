ssl_psk: ssl_psk.c
	gcc ssl_psk.c $(shell python2.7-config --cflags) $(shell python2.7-config --ldflags) \
		-shared -fPIC -o _ssl_psk.so -lssl -Wall -O2
