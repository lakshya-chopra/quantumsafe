// SPDX-License-Identifier: Apache-2.0 AND MIT
#ifndef TLSTEST_HELPERS_H_
#define TLSTEST_HELPERS_H_


#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>

int create_cert_key(OSSL_LIB_CTX *libctx, char *algname, char *certfilename,
                    char *privkeyfilename);

int create_tls1_3_ctx_pair(OSSL_LIB_CTX *libctx, SSL_CTX **sctx, SSL_CTX **cctx,
                           char *certfile, char *privkeyfile);

int create_tls_objects(SSL_CTX *serverctx, SSL_CTX *clientctx, SSL **sssl,
                       SSL **cssl);

int create_tls_connection(SSL *serverssl, SSL *clientssl, int want);

SSL_CTX *create_ssl_ctx(OSSL_LIB_CTX *libctx, const char *privkeyfile, const char *certfile);

#endif