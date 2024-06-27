#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "tlstest_helpers.h"
// #include "./oqs-provider/test/test_common.h"

static OSSL_provider_init_fn oqs_provider_init;

static OSSL_LIB_CTX *libctx = NULL;
static char *configfile = NULL;
static char *certsdir = NULL;

static char *signame = "dilithium3";
#ifndef OPENSSL_SYS_VMS
const char *sep = "/";
#else
const char *sep = "";
#endif

char certpath[300];
char privkeypath[300];

/** \brief Name of the oqsprovider. */
static const char *kOQSProviderName = "oqsprovider";

/** \brief Tries to load the oqsprovider named "oqsprovider".
 *
 * \param libctx Context of the OpenSSL library in which to load the
 * oqsprovider.
 *
 * \returns 0 if success, else -1. */
static int load_oqs_provider(OSSL_LIB_CTX *libctx, const char *configfile)
{
    OSSL_PROVIDER *provider;
    int ret;

    // ret = OSSL_LIB_CTX_load_config(libctx, configfile);
    // if (ret != 0)
    // {
    //     fprintf(stderr,
    //             "`OSSL_LIB_CTX_load_config` returned %i, but 0 was expected\n",
    //             ret);
    //     return -1;
    // }

    ret = OSSL_PROVIDER_available(libctx, kOQSProviderName);
    if (ret != 0)
    {
        fprintf(stderr,
                "`OSSL_PROVIDER_available` returned %i, but 0 was expected\n",
                ret);
        return -1;
    }

    provider = OSSL_PROVIDER_load(libctx, kOQSProviderName);
    if (provider == NULL) {
        fputs("`OSSL_PROVIDER_load` failed\n", stderr);
        return -1;
    }

    const char *provname = OSSL_PROVIDER_get0_name(provider);

    // if (!strcmp(provname, PROVIDER_NAME_OQS))
    //     void vctx;
    //     return OSSL_PROVIDER_get_capabilities(provider, "TLS-SIGALG",
    //                                           test_signature, vctx); //gets the capabilities & passes it onto the test_signature method
    // else
    //     return 1;

    return 0;
}

void print_certificate(const char *cert_path) {
    FILE *fp = fopen(cert_path, "r");
    if (fp == NULL) {
        fprintf(stderr, "Unable to open file %s\n", cert_path);
        return;
    }

    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (cert == NULL) {
        fprintf(stderr, "Error reading certificate from file %s\n", cert_path);
        ERR_print_errors_fp(stderr);
        fclose(fp);
        return;
    }

    // Create a BIO for output
    BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (out == NULL) {
        fprintf(stderr, "Error creating BIO for stdout\n");
        ERR_print_errors_fp(stderr);
        X509_free(cert);
        fclose(fp);
        return;
    }

    // Print the certificate
    if (X509_print(out, cert) != 1) { //print to out & then bio to -> STDOUT
        fprintf(stderr, "Error printing certificate\n");
        ERR_print_errors_fp(stderr);
    }

    // Free resources
    BIO_free(out);
    X509_free(cert);
    fclose(fp);
}

void print_private_key(const char *privkeyfile) {
    FILE *fp;
    EVP_PKEY *pkey = NULL;
    
    // Open the private key file
    fp = fopen(privkeyfile, "r");
    if (fp == NULL) {
        perror("Error opening private key file");
        return;
    }
    
    // Load private key from file
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (pkey == NULL) {
        fprintf(stderr, "Error loading private key from file\n");
        ERR_print_errors_fp(stderr);
        fclose(fp);
        return;
    }
    
    // Close the file
    fclose(fp);
    
    // Print the private key in human-readable format
    printf("Private Key:\n");
    PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
    
    // Free the EVP_PKEY structure
    EVP_PKEY_free(pkey);
}

int main(int argc, char *argv[])
{
    // OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    // OpenSSL_add_all_algorithms();

    printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));

    int ret;

    libctx = OSSL_LIB_CTX_new(); // to initialize OpenSSL
    if (libctx == NULL)
    {
        fputs("`OSSL_LIB_CTX_new` failed. Cannot initialize OpenSSL.\n",
              stderr);
        return 1;
    }

    //  get the certs
    if (argc != 3)
    {
        printf("\nPlease enter all the required args: configfile & certsdire\n");
        OSSL_LIB_CTX_free(libctx);
        return 2;
    }
    else
    {

        configfile = argv[1];
        certsdir = argv[2];

        // only libctx can be used with providers
        ret = load_oqs_provider(libctx, configfile);

        if (ret != 0)
        {
            fputs("`load_oqs_provider` failed. Dumping OpenSSL error queue.\n",
                  stderr);
            ERR_print_errors_fp(stderr);
            OSSL_LIB_CTX_free(libctx);
            return 2;
        }

        // set the path to the cert & the priv key

        sprintf(certpath, "%s%s%s%s", certsdir, sep, signame, "_srv.crt");
        sprintf(privkeypath, "%s%s%s%s", certsdir, sep, signame, "_srv.key");

        printf("cert path: %s\n",certpath);
        printf("priv key path: %s\n",privkeypath);

        printf("\nCertificate contents: \n");
        print_certificate(certpath);

        
        printf("\nPriv Key contents: \n");
        print_private_key(privkeypath);

    //     SSL_CTX *cctx = NULL, *sctx = NULL;
    // SSL *clientssl = NULL, *serverssl = NULL;

    //     create_tls1_3_ctx_pair(libctx,&sctx,&cctx,certpath,privkeypath);
        SSL_CTX * ssl_ctx = create_ssl_ctx(libctx,privkeypath,certpath); 

        // create SSL ctx and load the certs
    }

    OSSL_LIB_CTX_free(libctx);


    printf("\nCode has run successfully!\n");

    return 0;
}

// #include <stdio.h>
// #include <openssl/crypto.h>
// #include <openssl/err.h>
// #include <openssl/provider.h>
// #include <openssl/evp.h>
// #include <openssl/pem.h>
// #include <openssl/core.h>
// #include <openssl/ssl.h>

// static const char *kOQSProviderName = "liboqsprovider";

// static int load_oqs_provider(OSSL_LIB_CTX *libctx) {
//     OSSL_PROVIDER *provider;
//     int ret;

//     provider = OSSL_PROVIDER_load(libctx, kOQSProviderName);
//     if (provider == NULL) {
//         fputs("`OSSL_PROVIDER_load` failed\n", stderr);
//         return -1;
//     }

//     ret = OSSL_PROVIDER_available(libctx, kOQSProviderName);
//     if (ret != 1) {
//         fprintf(stderr, "`OSSL_PROVIDER_available` returned %i, but 1 was expected\n", ret);
//         return -1;
//     }

//     ret = OSSL_PROVIDER_self_test(provider);
//     if (ret != 1) {
//         fprintf(stderr, "`OSSL_PROVIDER_self_test` failed with returned code %i\n", ret);
//         return -1;
//     }

//     return 0;
// }

// static void list_ciphers(OSSL_LIB_CTX *libctx) {
//     EVP_CIPHER *cipher = NULL;
//     OSSL_PROVIDER *provider = NULL;

//     printf("Available Ciphers:\n");
//     for (EVP_CIPHER_fetch(libctx, NULL, NULL); (cipher = EVP_CIPHER_fetch(libctx, NULL, NULL)); ){
//             printf("here\n");

//         provider = EVP_CIPHER_get0_provider(cipher);
//         if (provider && strcmp(OSSL_PROVIDER_get0_name(provider), kOQSProviderName) == 0) {
//             printf("  %s\n", EVP_CIPHER_get0_name(cipher));
//         }
//     }
// }

// static void list_digests(OSSL_LIB_CTX *libctx) {
//     EVP_MD *md = NULL;
//     OSSL_PROVIDER *provider = NULL;

//     printf("Available Digests:\n");
//     for (EVP_MD_fetch(libctx, NULL, NULL); (md = EVP_MD_fetch(libctx, NULL, NULL)) != NULL; EVP_MD_free(md)) {

//             printf("here\n");

//         provider = EVP_MD_get0_provider(md);

//         if (provider == 0) {
//             printf("here\n");
//             printf("  %s\n", EVP_MD_get0_name(md));
//         }
//     }
// }

// int main() {
//     SSL_library_init();
//     OPENSSL_add_all_algorithms_noconf();

//     printf("OpenSSL Version: %s\n", OpenSSL_version(OPENSSL_VERSION));

//     OSSL_LIB_CTX *libctx;
//     int ret;

//     libctx = OSSL_LIB_CTX_new(); // to initialize OpenSSL
//     if (libctx == NULL) {
//         fputs("`OSSL_LIB_CTX_new` failed. Cannot initialize OpenSSL.\n", stderr);
//         return 1;
//     }

//     ret = load_oqs_provider(libctx);
//     if (ret != 0) {
//         fputs("`load_oqs_provider` failed. Dumping OpenSSL error queue.\n", stderr);
//         ERR_print_errors_fp(stderr);
//         OSSL_LIB_CTX_free(libctx);
//         return 2;
//     }

//     list_ciphers(libctx);
//     list_digests(libctx);

//     OSSL_LIB_CTX_free(libctx);

//     return 0;
// }
