#include "openssl-compat.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
static OSSL_PROVIDER *g_provider_legacy;
static OSSL_PROVIDER *g_provider_default;
#endif

#define OPENSSL_COMPAT_opaque(OBJECT) \
OBJECT *OBJECT##_new(void) \
{ \
    OBJECT *object = (OBJECT *)OPENSSL_malloc(sizeof(OBJECT)); \
    if (object) { \
        memset(object, 0, sizeof(OBJECT)); \
    } \
    return object; \
} \
void OBJECT##_free(OBJECT *object) \
{ \
    if (object) { \
        OBJECT##_cleanup(object); \
        OPENSSL_free(object); \
    } \
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
EVP_PKEY *X509_get0_pubkey(X509 *x)
{
    EVP_PKEY *pkey;

    pkey = X509_get_pubkey(x);
    if (!pkey) {
        return NULL;
    }

    /* HACK: OpenSSL 1.0.2 will store a reference inside X509 so
     *       freeing the returned copy will not destroy the object */
    assert(pkey->references > 1);
    EVP_PKEY_free(pkey);
    return pkey;
}

EVP_PKEY *X509_REQ_get0_pubkey(X509_REQ *x)
{
    EVP_PKEY *pkey;

    pkey = X509_REQ_get_pubkey(x);
    if (!pkey) {
        return NULL;
    }

    /* HACK: OpenSSL 1.0.2 will store a reference inside X509_REQ so
     *       freeing the returned copy will not destroy the object */
    assert(pkey->references > 1);
    EVP_PKEY_free(pkey);
    return pkey;
}
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

#if OPENSSL_VERSION_NUMBER < 0x10101000L
OPENSSL_COMPAT_opaque(EVP_MD_CTX);
OPENSSL_COMPAT_opaque(HMAC_CTX);

int ASN1_TIME_compare(const ASN1_TIME *a, const ASN1_TIME *b)
{
    int day, sec;

    if (!ASN1_TIME_diff(&day, &sec, b, a))
        return -2;
    if (day > 0 || sec > 0)
        return 1;
    if (day < 0 || sec < 0)
        return -1;
    return 0;
}
#endif /* OPENSSL_VERSION_NUMBER < 0x10101000L */

#if OPENSSL_VERSION_NUMBER < 0x30000000L

EVP_MAC *EVP_MAC_fetch(
        void *libctx,
        const char *algorithm,
        const char *properties)
{
    if (libctx || strcmp(algorithm, "HMAC") || properties) {
        abort();
    }

    return (EVP_MAC *)0xdeadbeef;
}

void EVP_MAC_free(EVP_MAC *mac)
{
    (void)mac;
}

EVP_MAC_CTX *EVP_MAC_CTX_new(EVP_MAC *mac)
{
    if (!mac) {
        abort();
    }

    return HMAC_CTX_new();
}

int EVP_MAC_init(
        EVP_MAC_CTX *ctx,
        const unsigned char *key,
        size_t keylen,
        const OSSL_PARAM params[])
{
    const EVP_MD *md;
    int i;

    md = NULL;
    for (i = 0; params[i].key; ++i) {
        if (strcmp(params[i].key, OSSL_MAC_PARAM_DIGEST) == 0) {
            md = EVP_get_digestbyname(params[i].value);
        }
    }

    return HMAC_Init_ex(ctx, key, keylen, md, NULL);
}

int EVP_MAC_final(
        EVP_MAC_CTX *ctx,
        unsigned char *out,
        size_t *outl,
        size_t outsize)
{
    unsigned int outlen;
    int ret;

    (void)outsize; /* Take care of yourself */
    ret = HMAC_Final(ctx, out, &outlen);
    *outl = outlen;
    return ret;
}

OSSL_PARAM OSSL_PARAM_construct_utf8_string(
        const char *key, char *buf, size_t bsize)
{
    OSSL_PARAM value = {.key = key, .value = buf};
    if (!key || !buf || bsize) {
        abort();
    }
    return value;
}

OSSL_PARAM OSSL_PARAM_construct_end(void)
{
    static const OSSL_PARAM kValue = {.key = NULL, .value = NULL};
    return kValue;
}

#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */

int OpenSSL_initialize(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    OpenSSL_add_all_algorithms();
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (!(g_provider_legacy = OSSL_PROVIDER_load(NULL, "legacy"))) {
        return -1;
    }

    if (!(g_provider_default = OSSL_PROVIDER_load(NULL, "default"))) {
        return -1;
    }
#endif

    return 0;
}

void OpenSSL_shutdown(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (g_provider_default) {
        OSSL_PROVIDER_unload(g_provider_default);
        g_provider_default = NULL;
    }

    if (g_provider_legacy) {
        OSSL_PROVIDER_unload(g_provider_legacy);
        g_provider_legacy = NULL;
    }
#endif
}
