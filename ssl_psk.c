#include <Python.h>

#include "openssl/rsa.h"
#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/rand.h"

#define X509_NAME_MAXLEN 256
/* from _ssl.c */
typedef struct {
    PyObject_HEAD
    PyObject*           Socket;         /* Socket on which we're layered */
    SSL_CTX*            ctx;
    SSL*                ssl;
    X509*               peer_cert;
    char                server[X509_NAME_MAXLEN];
    char                issuer[X509_NAME_MAXLEN];
    int                 shutdown_seen_zero;
} PySSLObject;


static PyObject * Error;

static PyObject* python_psk_callback = NULL;
static const char* psk_identity = "Client_identity";


static unsigned int psk_server_cb(SSL *ssl, const char *identity,
                                  unsigned char *psk, unsigned int max_psk_len) {
    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();
    if(python_psk_callback == NULL) abort();
    PyObject* result = PyObject_CallFunction(python_psk_callback, "l", (long)ssl);
    if(result == NULL) {
      fprintf(stderr, "psk_callback returned error\n");
      return 0;
    }
    int length = -1;
    char* psk_buffer;
    if(PyArg_Parse(result, "s#", &psk_buffer, &length) == 0) {
      fprintf(stderr, "pyarg_parse returned error\n");
      return 0;
    }
    if(length >= max_psk_len) {
      fprintf(stderr, "psk buffer too short (%d, needed %d)\n", max_psk_len, length);
      return 0;
    }
    memcpy(psk, psk_buffer, length);

    Py_DECREF(result);
    PyGILState_Release(gstate);
    return length;
}


static unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity,
                                  unsigned int max_identity_len, unsigned char *psk,
                                  unsigned int max_psk_len) {
  int length = psk_server_cb(ssl, NULL, psk, max_psk_len);
  if(length == 0) return 0;
  if(strlen(psk_identity) >= max_identity_len) {
    fprintf(stderr, "psk_identity buffer too short\n");
    return 0;
  }
  strcpy(identity, psk_identity);
  return length;
}

PyObject* ssl_set_python_psk_callback(PyObject* self, PyObject* args) {
  PyObject* func;
  if (!PyArg_ParseTuple(args, "O", &func))
    return NULL;
  python_psk_callback = func;
  Py_RETURN_NONE;
}

PyObject* ssl_set_psk_callback(PyObject* self, PyObject* args) {
  PyObject* sock;
  if (!PyArg_ParseTuple(args, "O", &sock))
    return NULL;
  SSL* ssl = ((PySSLObject*)sock)->ssl;
  SSL_set_psk_client_callback(ssl, psk_client_cb);
  return Py_BuildValue("l", (long)ssl);
}

PyObject* set_psk_server_callback(PyObject* self, PyObject* args) {
  PyObject* sock;
  if (!PyArg_ParseTuple(args, "O", &sock))
    return NULL;
  SSL* ssl = ((PySSLObject*)sock)->ssl;
  SSL_set_accept_state(ssl);
  SSL_set_psk_server_callback(ssl, psk_server_cb);
  if(!SSL_use_psk_identity_hint(ssl, psk_identity)) {
    PyErr_SetString(Error, "use_psk_identity_hint failed");
    return NULL;
  }
  return Py_BuildValue("l", (long)ssl);
}

static PyMethodDef Methods[] = {
    {"set_psk_callback",  ssl_set_psk_callback, METH_VARARGS, ""},
    {"set_python_psk_callback",  ssl_set_python_psk_callback, METH_VARARGS, ""},
    {"set_psk_server_callback", set_psk_server_callback, METH_VARARGS, ""},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
init_ssl_psk(void)
{
    PyObject* m = Py_InitModule("_ssl_psk", Methods);
    if (m == NULL)
        return;

    Error = PyErr_NewException("_ssl_psk.error", NULL, NULL);
    Py_INCREF(Error);
    PyModule_AddObject(m, "error", Error);
}
