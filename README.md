## An implementation of Quantum safe SSL/TLS using OpenSSL + the oqs-provider

- Currently, this only loads the certificates and the private key files into the `SSL_CTX`, and prints them too (for debugging purposes). More work to be added soon, such as creating a dedicated PQ TLS Channel with using only quantum safe KEMs & Signature schemes.

- For info regarding the setup, [check this out](https://github.com/lakshya-chopra/openssl_installation/blob/main/oqs_provider_setup.md)

- The `env.sh` contains all the required environment variables to run this code.

### Compile `main.c` using (assuming you've run `env.sh`)
```
gcc tlstest_helpers.c -c
gcc tlstest_helpers.o main.c -o main -L$BUILD_DIR/lib -L$BUILD_DIR/lib64 -lssl -lcrypto -l:oqsprovider.so -loqs
```
and run it:
```
./main $BUILD_DIR/ssl/openssl.cnf $WORKSPACE/certsdir
```

