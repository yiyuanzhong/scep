#ifndef SCEP_OPENSSL_COMPAT_H
#define SCEP_OPENSSL_COMPAT_H

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#include <openssl/x509.h>

#define X509_set1_notBefore     X509_set_notBefore
#define X509_set1_notAfter      X509_set_notAfter
#define X509_get0_notBefore     X509_get_notBefore
#define X509_get0_notAfter      X509_get_notAfter
#define X509_get0_serialNumber  X509_get_serialNumber

#define EVP_PKEY_get0_RSA(x) (x->pkey.rsa)

extern EVP_PKEY *X509_get0_pubkey(const X509 *x);
extern EVP_PKEY *X509_REQ_get0_pubkey(X509_REQ *x); /* HACK: non-const */
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

#if OPENSSL_VERSION_NUMBER < 0x10101000L
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define RSA_get0_n(x) (x->n)

extern HMAC_CTX *HMAC_CTX_new(void);
extern void HMAC_CTX_free(HMAC_CTX *ctx);

extern EVP_MD_CTX *EVP_MD_CTX_new(void);
extern void EVP_MD_CTX_free(EVP_MD_CTX *ctx);

extern int ASN1_TIME_compare(const ASN1_TIME *a, const ASN1_TIME *b);
#endif /* OPENSSL_VERSION_NUMBER < 0x10101000L */

extern int OpenSSL_initialize(void);
extern void OpenSSL_shutdown(void);

#endif /* SCEP_OPENSSL_COMPAT_H */
