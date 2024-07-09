#!/bin/sh

export WORKSPACE=~/quantumsafe # set this to a working dir of your choice
export BUILD_DIR=$WORKSPACE/build # this will contain all the build artifacts

# These env vars need to be set for the oqsprovider to be used when using OpenSSL
export OPENSSL_CONF=$BUILD_DIR/ssl/openssl.cnf
export OPENSSL_MODULES=$BUILD_DIR/lib
export OPENSSL_APP=$BUILD_DIR/bin/openssl
export LD_LIBRARY_PATH=LD_LIBRARY_PATH:$BUILD_DIR/lib  
