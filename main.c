#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/provider.h>

extern OSSL_provider_init_fn oqs_provider_init;

/** \brief Name of the oqsprovider. */
static const char *kOQSProviderName = "oqsprovider";

/** \brief Tries to load the oqsprovider named "oqsprovider".
 *
 * \param libctx Context of the OpenSSL library in which to load the
 * oqsprovider. 
 *
 * \returns 0 if success, else -1. */
static int load_oqs_provider(OSSL_LIB_CTX *libctx)
{
    OSSL_PROVIDER *provider;
    int ret;

    ret = OSSL_PROVIDER_available(libctx, kOQSProviderName);
    if (ret != 0) {
        fprintf(stderr,
                "`OSSL_PROVIDER_available` returned %i, but 0 was expected\n",
                ret);
        return -1;
    }

    // ret = OSSL_PROVIDER_add_builtin(libctx, kOQSProviderName,
    //                                 oqs_provider_init); //for static loading (.a)
    // if (ret != 1) {
    //     fprintf(stderr,
    //             "`OSSL_PROVIDER_add_builtin` failed with returned code %i\n",
    //             ret);
    //     return -1;
    // }

    provider = OSSL_PROVIDER_load(libctx, kOQSProviderName); //for dynamic loading (.so)
    if (provider == NULL) {
        fputs("`OSSL_PROVIDER_load` failed\n", stderr);
        return -1;
    }

    ret = OSSL_PROVIDER_available(libctx, kOQSProviderName);
    if (ret != 1) {
        fprintf(stderr,
                "`OSSL_PROVIDER_available` returned %i, but 1 was expected\n",
                ret);
        return -1;
    }

    ret = OSSL_PROVIDER_self_test(provider);
    if (ret != 1) {
        fprintf(stderr,
                "`OSSL_PROVIDER_self_test` failed with returned code %i\n",
                ret);
        return -1;
    }

    return 0;
}

int main()
{
    OSSL_LIB_CTX *libctx;
    int ret;

    libctx = OSSL_LIB_CTX_new(); // to initialize OpenSSL
    if (libctx == NULL) {
        fputs("`OSSL_LIB_CTX_new` failed. Cannot initialize OpenSSL.\n",
              stderr);
        return 1;
    }

    ret = load_oqs_provider(libctx);
    if (ret != 0) {
        fputs("`load_oqs_provider` failed. Dumping OpenSSL error queue.\n",
              stderr);
        ERR_print_errors_fp(stderr);
        OSSL_LIB_CTX_free(libctx);
        return 2;
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
