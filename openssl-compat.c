#include "openssl-compat.h"

#include <assert.h>
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
EVP_PKEY *X509_get0_pubkey(const X509 *x)
{
    return (x && x->cert_info && x->cert_info->key) ? x->cert_info->key->pkey : NULL;
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
