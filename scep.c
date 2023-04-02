#include "scep.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#define SCEP_RSA_MIN_BITS 2048

struct scep_extension {
    struct scep_extension *next;
    char *value;
    int nid;
};

struct scep {
    int NID_SCEP_messageType;
    int NID_SCEP_pkiStatus;
    int NID_SCEP_failInfo;
    int NID_SCEP_senderNonce;
    int NID_SCEP_recipientNonce;
    int NID_SCEP_transactionID;
    int NID_SCEP_extensionReq;

    X509 *cert;
    EVP_PKEY *pkey;
    const EVP_MD *md;
    STACK_OF(X509) *chain;
    struct scep_extension *extensions;
};

struct scep_pkiMessage_attributes {
    ASN1_PRINTABLESTRING *transactionID;
    ASN1_PRINTABLESTRING *messageType;
    ASN1_PRINTABLESTRING *pkiStatus;
    ASN1_PRINTABLESTRING *failInfo;
    ASN1_OCTET_STRING    *senderNonce;
    ASN1_OCTET_STRING    *recipientNonce;
};

struct scep_pkiMessage {
    PKCS7 *pkcs7;
    BIO *payload;
    X509 *signer;
    enum messageType messageType;

    struct scep_pkiMessage_attributes auth_attr;
};

struct scep_PKCSReq {
    struct scep_pkiMessage *m;
    X509_REQ *csr;
    RSA *csrkey;
    int valid;
    ASN1_PRINTABLESTRING *challengePassword;
};

struct scep_CertRep {
    PKCS7 *pkcs7;
    X509 *cert;
};

static char *trim(char *s)
{
    char *p;
    char *q;

    while (*s && (*s == ' ' || *s == '\t')) {
        ++s;
    }

    for (p = q = s; *q; ++q) {
        if (*q != ' ' && *q != '\t') {
            p = q;
        }
    }

    if (*p) {
        p[1] = '\0';
    }

    return s;
}

static int scep_oid2nid(const char *oid)
{
    int nid;

    nid = OBJ_txt2nid(oid);
    if (nid != NID_undef) {
        return nid;
    }

    return OBJ_create(oid, NULL, NULL);
}

static int scep_get_rsa_key_bits(EVP_PKEY *pkey)
{
    const BIGNUM *bn;
    const RSA *rsa;
    int bytes;

    rsa = EVP_PKEY_get0_RSA(pkey);
    if (!rsa) {
        return -1;
    }

    bn = RSA_get0_n(rsa);
    if (!bn) {
        return -1;
    }

    bytes = BN_num_bytes(bn);
    if (bytes < 0) {
        return -1;
    }

    return bytes * 8;
}

struct scep *scep_new(void)
{
    struct scep *scep;

    scep = (struct scep *)malloc(sizeof(*scep));
    if (!scep) {
        return NULL;
    }

    memset(scep, 0, sizeof(*scep));

    scep->NID_SCEP_messageType    = scep_oid2nid("2.16.840.1.113733.1.9.2");
    scep->NID_SCEP_pkiStatus      = scep_oid2nid("2.16.840.1.113733.1.9.3");
    scep->NID_SCEP_failInfo       = scep_oid2nid("2.16.840.1.113733.1.9.4");
    scep->NID_SCEP_senderNonce    = scep_oid2nid("2.16.840.1.113733.1.9.5");
    scep->NID_SCEP_recipientNonce = scep_oid2nid("2.16.840.1.113733.1.9.6");
    scep->NID_SCEP_transactionID  = scep_oid2nid("2.16.840.1.113733.1.9.7");
    scep->NID_SCEP_extensionReq   = scep_oid2nid("2.16.840.1.113733.1.9.8");

    if (scep->NID_SCEP_messageType    == NID_undef ||
        scep->NID_SCEP_pkiStatus      == NID_undef ||
        scep->NID_SCEP_failInfo       == NID_undef ||
        scep->NID_SCEP_senderNonce    == NID_undef ||
        scep->NID_SCEP_recipientNonce == NID_undef ||
        scep->NID_SCEP_transactionID  == NID_undef ||
        scep->NID_SCEP_extensionReq   == NID_undef ){

        free(scep);
        return NULL;
    }

    return scep;
}

static int scep_load_subject_extension(struct scep *scep, char *buffer)
{
    struct scep_extension *e;
    struct scep_extension *p;
    char *value;
    char *copy;
    char *key;
    int nid;

    if (!*buffer || *buffer == '#') {
        return 0;
    }

    value = strchr(buffer, '=');
    if (!value) {
        return -1;
    }

    *value++ = '\0';
    key = trim(buffer);
    value = trim(value);
    if (!*key || !*value) {
        return -1;
    }

    nid = OBJ_txt2nid(key);
    if (nid == NID_undef) {
        return -1;
    }

    copy = strdup(value);
    if (!copy) {
        return -1;
    }

    e = (struct scep_extension *)malloc(sizeof(*e));
    if (!e) {
        free(copy);
        return -1;
    }

    memset(e, 0, sizeof(*e));
    e->value = copy;
    e->nid = nid;

    if (!(p = scep->extensions)) {
        scep->extensions = e;
        return 0;
    }

    while (p->next) {
        p = p->next;
    }

    p->next = e;
    return 0;
}

int scep_load_subject_extensions(struct scep *scep, const char *filename)
{
    char line[256];
    BIO *bp;
    int len;

    bp = BIO_new_file(filename, "r");
    if (!bp) {
        return -1;
    }

    while ((len = BIO_gets(bp, line, sizeof(line))) > 0) {
        if (line[len - 1] == '\n') {
            line[--len] = '\0';
        }

        if (scep_load_subject_extension(scep, line)) {
            len = -1;
            break;
        }
    }

    BIO_free_all(bp);
    return len >= 0 ? 0 : -1;
}

void scep_free(struct scep *scep)
{
    struct scep_extension *p;
    X509 *cert;
    int num;
    int i;

    if (scep->chain) { /* Signing cert is included */
        assert(scep->pkey);
        EVP_PKEY_free(scep->pkey);
        num = sk_X509_num(scep->chain);
        for (i = 0; i < num; ++i) {
            cert = sk_X509_value(scep->chain, i);
            X509_free(cert);
        }

        sk_X509_free(scep->chain);
    }

    while ((p = scep->extensions)) {
        scep->extensions = p->next;
        free(p->value);
        free(p);
    }

    free(scep);
}

static int scep_check_digest_algo(int nid)
{
    /* There're many algos, just block some known bad ones */
    switch (nid) {
    case NID_undef:
    case NID_md2:
    case NID_md4:
    case NID_md5:
        return -1;
    }

    return 0;
}

static int scep_check_signature_algo(int nid)
{
    const EVP_MD *md;

    /* Explicit allow naked RSA without any hash */
    switch (nid) {
    case NID_rsaEncryption:
        return 0;
    }

    /* Otherwise the algorithm should contain a digest */
    md = EVP_get_digestbynid(nid);
    if (!md) {
        return -1;
    }

    nid = EVP_MD_nid(md);
    return scep_check_digest_algo(nid);
}

static int scep_PKCS7_SIGNER_INFO_check_algo(PKCS7_SIGNER_INFO *si)
{
    X509_ALGOR *digest;
    X509_ALGOR *sign;
    int nid;

    PKCS7_SIGNER_INFO_get0_algs(si, NULL, &digest, &sign);
    if (!digest || !sign) {
        return -1;
    }

    nid = OBJ_obj2nid(digest->algorithm);
    if (scep_check_digest_algo(nid)) {
        return -1;
    }

    nid = OBJ_obj2nid(sign->algorithm);
    if (scep_check_signature_algo(nid)) {
        return -1;
    }

    return 0;
}

static X509 *scep_load_certificate_only(
        const char *certfile,
        int certpem,
        const EVP_MD **md)
{
    X509 *cert;
    BIO *bp;
    int nid;

    bp = BIO_new_file(certfile, "rb");
    if (!bp) {
        return NULL;
    }

    if (certpem) {
        cert = PEM_read_bio_X509(bp, NULL, NULL, NULL);
    } else {
        cert = d2i_X509_bio(bp, NULL);
    }

    if (!cert) {
        BIO_free_all(bp);
        return NULL;
    }

    BIO_free_all(bp);
    if (X509_get_version(cert) < 2) { /* X509 V3 */
        X509_free(cert);
        return NULL;
    }

    if (!md) {
        return cert;
    }

    nid = X509_get_signature_nid(cert);
    if (scep_check_signature_algo(nid)) {
        X509_free(cert);
        return NULL;
    }

    *md = EVP_get_digestbynid(nid);
    if (!*md) {
        X509_free(cert);
        return NULL;
    }

    return cert;
}

int scep_load_certificate(
        struct scep *scep,
        const char *certfile,
        int certpem,
        const char *keyfile,
        int keypem,
        const char *keypass)
{
    STACK_OF(X509) *chain;
    const EVP_MD *md;
    EVP_PKEY *pkey;
    X509 *cert;
    BIO *bp;

    if (!scep || scep->cert) {
        return -1;
    }

    cert = scep_load_certificate_only(certfile, certpem, &md);
    if (!cert) {
        return -1;
    }

    bp = BIO_new_file(keyfile, "rb");
    if (!bp) {
        X509_free(cert);
        return -1;
    }

    if (keypem) {
        pkey = PEM_read_bio_PrivateKey(bp, NULL, NULL, (void *)keypass);
    } else {
        pkey = d2i_PrivateKey_bio(bp, NULL);
    }

    if (!pkey) {
        BIO_free_all(bp);
        X509_free(cert);
        return -1;
    }

    BIO_free_all(bp);

    chain = sk_X509_new_null();
    if (!chain) {
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return -1;
    }

    if (sk_X509_push(chain, cert) == 0) {
        sk_X509_free(chain);
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return -1;
    }

    assert(!scep->chain);
    assert(!scep->cert);
    assert(!scep->pkey);
    assert(!scep->md);

    scep->chain = chain;
    scep->cert = cert;
    scep->pkey = pkey;
    scep->md = md;
    return 0;
}

int scep_load_certificate_chain(
        struct scep *scep,
        const char *certfile,
        int certpem)
{
    STACK_OF(X509) *chain;
    X509 *cert;

    if (!scep || !scep->cert) {
        return -1;
    }

    cert = scep_load_certificate_only(certfile, certpem, NULL);
    if (!cert) {
        return -1;
    }

    if (scep->chain) {
        if (sk_X509_push(scep->chain, cert) == 0) {
            X509_free(cert);
            return -1;
        }

    } else {
        chain = sk_X509_new_null();
        if (!chain) {
            return -1;
        }

        if (sk_X509_push(chain, scep->cert) == 0 ||
            sk_X509_push(chain, cert) == 0       ){

            sk_X509_free(chain);
            X509_free(cert);
            return -1;
        }

        scep->chain = chain;
    }

    return 0;
}

static int scep_decrypt(struct scep *scep, BIO **bpp)
{
    PKCS7 *pkcs7;
    BIO *wbp;
    BIO *rbp;

    rbp = *bpp;
    pkcs7 = d2i_PKCS7_bio(rbp, NULL);
    if (!pkcs7) {
        return -1;
    }

    if (!PKCS7_type_is_enveloped(pkcs7)) {
        PKCS7_free(pkcs7);
        return -1;
    }

    wbp = BIO_new(BIO_s_mem());
    if (!wbp) {
        PKCS7_free(pkcs7);
        return -1;
    }

    if (PKCS7_decrypt(pkcs7, scep->pkey, scep->cert, wbp, 0) != 1) {
        BIO_free_all(wbp);
        PKCS7_free(pkcs7);
        return -1;
    }

    PKCS7_free(pkcs7);
    BIO_free_all(rbp);
    *bpp = wbp;
    return 0;
}

static ASN1_TYPE *scep_get_req_attribute(
        X509_REQ *req,
        int nid, int expected_type)
{
    X509_ATTRIBUTE *a;
    ASN1_TYPE *type;
    int count;
    int loc;

    loc = X509_REQ_get_attr_by_NID(req, nid, -1);
    if (loc < 0) {
        return NULL;
    }

    a = X509_REQ_get_attr(req, loc);
    if (!a) {
        return NULL;
    }

    count = X509_ATTRIBUTE_count(a);
    if (count <= 0) {
        return NULL;
    }

    type = X509_ATTRIBUTE_get0_type(a, 0);
    if (!type) {
        return NULL;
    }

    if (ASN1_TYPE_get(type) != expected_type) {
        return NULL;
    }

    return type;
}

static ASN1_TYPE *scep_get_attribute(
        STACK_OF(X509_ATTRIBUTE) *attributes,
        int nid, int expected_type)
{
    X509_ATTRIBUTE *a;
    ASN1_TYPE *type;
    int count;
    int loc;

    loc = X509at_get_attr_by_NID(attributes, nid, -1);
    if (loc < 0) {
        return NULL;
    }

    a = X509at_get_attr(attributes, loc);
    if (!a) {
        return NULL;
    }

    count = X509_ATTRIBUTE_count(a);
    if (count <= 0) {
        return NULL;
    }

    type = X509_ATTRIBUTE_get0_type(a, 0);
    if (!type) {
        return NULL;
    }

    if (ASN1_TYPE_get(type) != expected_type) {
        return NULL;
    }

    return type;
}

static ASN1_PRINTABLESTRING *scep_printable_string(const char *str)
{
    ASN1_PRINTABLESTRING *copy;

    copy = ASN1_PRINTABLESTRING_new();
    if (!copy) {
        return NULL;
    }

    if (ASN1_STRING_set(copy, str, -1) != 1) {
        ASN1_PRINTABLESTRING_free(copy);
        return NULL;
    }

    return copy;
}

static int scep_add_printable_string(
        PKCS7_SIGNER_INFO *si, int nid, ASN1_PRINTABLESTRING *str)
{
    ASN1_PRINTABLESTRING *copy;

    copy = ASN1_STRING_dup(str);
    if (!copy) {
        return -1;
    }

    if (PKCS7_add_signed_attribute(
            si, nid, V_ASN1_PRINTABLESTRING, copy) != 1) {

        ASN1_PRINTABLESTRING_free(copy);
        return -1;
    }

    return 0;
}

static int scep_add_octet_string(
        PKCS7_SIGNER_INFO *si, int nid, ASN1_OCTET_STRING *str)
{
    ASN1_PRINTABLESTRING *copy;

    copy = ASN1_STRING_dup(str);
    if (!copy) {
        return -1;
    }

    if (PKCS7_add_signed_attribute(
            si, nid, V_ASN1_OCTET_STRING, copy) != 1) {

        ASN1_PRINTABLESTRING_free(copy);
        return -1;
    }

    return 0;
}

static ASN1_PRINTABLESTRING *scep_get_printable_string(
        STACK_OF(X509_ATTRIBUTE) *attributes,
        int nid)
{
    ASN1_TYPE *type;

    type = scep_get_attribute(attributes, nid, V_ASN1_PRINTABLESTRING);
    if (!type) {
        return NULL;
    }

    return type->value.printablestring;
}

static ASN1_PRINTABLESTRING *scep_get_req_printable_string(
        X509_REQ *req,
        int nid)
{
    ASN1_TYPE *type;

    type = scep_get_req_attribute(req, nid, V_ASN1_PRINTABLESTRING);
    if (!type) {
        return NULL;
    }

    return type->value.printablestring;
}

static ASN1_OCTET_STRING *scep_get_octet_string(
        STACK_OF(X509_ATTRIBUTE) *attributes,
        int nid)
{
    ASN1_TYPE *type;

    type = scep_get_attribute(attributes, nid, V_ASN1_OCTET_STRING);
    if (!type) {
        return NULL;
    }

    return type->value.octet_string;
}

static ASN1_OCTET_STRING *scep_nonce(void)
{
    ASN1_OCTET_STRING *s;
    unsigned char n[16];

    if (RAND_bytes(n, sizeof(n)) != 1) {
        return NULL;
    }

    s = ASN1_OCTET_STRING_new();
    if (!s) {
        return NULL;
    }

    if (ASN1_OCTET_STRING_set(s, n, sizeof(n)) != 1) {
        ASN1_OCTET_STRING_free(s);
        return NULL;
    }

    return s;
}

static void scep_pkiMessage_attributes_cleanup(
        struct scep_pkiMessage_attributes *a)
{
    if (a->transactionID) {
        ASN1_PRINTABLESTRING_free(a->transactionID);
        a->transactionID = NULL;
    }

    if (a->messageType) {
        ASN1_PRINTABLESTRING_free(a->messageType);
        a->messageType = NULL;
    }

    if (a->pkiStatus) {
        ASN1_PRINTABLESTRING_free(a->pkiStatus);
        a->pkiStatus = NULL;
    }

    if (a->failInfo) {
        ASN1_PRINTABLESTRING_free(a->failInfo);
        a->failInfo = NULL;
    }

    if (a->senderNonce) {
        ASN1_OCTET_STRING_free(a->senderNonce);
        a->senderNonce = NULL;
    }

    if (a->recipientNonce) {
        ASN1_OCTET_STRING_free(a->recipientNonce);
        a->recipientNonce = NULL;
    }
}

static int scep_pkiMessage_get_attributes(
        struct scep *scep,
        struct scep_pkiMessage_attributes *a,
        STACK_OF(X509_ATTRIBUTE) *auth_attr)
{
    a->transactionID = scep_get_printable_string(auth_attr,
            scep->NID_SCEP_transactionID);

    a->messageType = scep_get_printable_string(auth_attr,
            scep->NID_SCEP_messageType);

    a->pkiStatus = scep_get_printable_string(auth_attr,
            scep->NID_SCEP_pkiStatus);

    a->failInfo = scep_get_printable_string(auth_attr,
            scep->NID_SCEP_failInfo);

    a->senderNonce = scep_get_octet_string(auth_attr,
            scep->NID_SCEP_senderNonce);

    a->recipientNonce = scep_get_octet_string(auth_attr,
            scep->NID_SCEP_recipientNonce);

    return 0;
}

static int scep_pkiMessage_add_attributes(
        struct scep *scep, PKCS7_SIGNER_INFO *si,
        struct scep_pkiMessage_attributes *a)
{
    if (a->transactionID) {
        if (scep_add_printable_string(si,
            scep->NID_SCEP_transactionID, a->transactionID)) {
            return -1;
        }
    }

    if (a->messageType) {
        if (scep_add_printable_string(si,
            scep->NID_SCEP_messageType, a->messageType)) {
            return -1;
        }
    }

    if (a->pkiStatus) {
        if (scep_add_printable_string(si,
            scep->NID_SCEP_pkiStatus, a->pkiStatus)) {
            return -1;
        }
    }

    if (a->failInfo) {
        if (scep_add_printable_string(si,
            scep->NID_SCEP_failInfo, a->failInfo)) {
            return -1;
        }
    }

    if (a->senderNonce) {
        if (scep_add_octet_string(si,
            scep->NID_SCEP_senderNonce, a->senderNonce)) {
            return -1;
        }
    }

    if (a->recipientNonce) {
        if (scep_add_octet_string(si,
            scep->NID_SCEP_recipientNonce, a->recipientNonce)) {
            return -1;
        }
    }

    return 0;
}

static int scep_pkiMessage_set_type(struct scep_pkiMessage *m)
{
    const ASN1_PRINTABLESTRING *mt;

    mt = m->auth_attr.messageType;
    if (!mt) {
        return -1;
    }

    if (mt->length == 1) {
        if (memcmp(mt->data, "3", 1) == 0) {
            m->messageType = messageType_CertRep;
            return 0;
        }
    } else if (mt->length == 2) {
        if (memcmp(mt->data, "19", 2) == 0) {
            m->messageType = messageType_PKCSReq;
            return 0;
        } else if (memcmp(mt->data, "20", 2) == 0) {
            m->messageType = messageType_GetCertInitial;
            return 0;
        } else if (memcmp(mt->data, "21", 2) == 0) {
            m->messageType = messageType_GetCert;
            return 0;
        } else if (memcmp(mt->data, "22", 2) == 0) {
            m->messageType = messageType_GetCRL;
            return 0;
        }
    }

    return -1;
}

struct scep_pkiMessage *scep_pkiMessage_new(
        struct scep *scep,
        BIO *bp,
        int allow_exposed_challenge_password)
{
    STACK_OF(PKCS7_SIGNER_INFO) *signers;
    STACK_OF(X509_ATTRIBUTE) *auth_attr;
    struct scep_pkiMessage *m;
    PKCS7_SIGNER_INFO *signer;
    EVP_PKEY *signkey;
    char buffer[1024];
    int signbits;
    PKCS7 *pkcs7;
    X509 *cert;
    BIO *rbp;
    BIO *wbp;
    int size;
    int ret;

    pkcs7 = d2i_PKCS7_bio(bp, NULL);
    if (!pkcs7) {
        return NULL;
    }

    if (!PKCS7_type_is_signed(pkcs7) || PKCS7_is_detached(pkcs7)) {
        PKCS7_free(pkcs7);
        return NULL;
    }

    signers = PKCS7_get_signer_info(pkcs7); /* Internal */
    if (sk_PKCS7_SIGNER_INFO_num(signers) <= 0) {
        PKCS7_free(pkcs7);
        return NULL;
    }

    rbp = PKCS7_dataInit(pkcs7, NULL);
    if (!rbp) {
        PKCS7_free(pkcs7);
        return NULL;
    }

    wbp = BIO_new(BIO_s_mem());
    if (!wbp) {
        BIO_free_all(rbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    /* Read the content once so the hash is calculated, but save the content to
     * another BIO so we can access later */

    for (;;) {
        size = BIO_read(rbp, buffer, sizeof(buffer));
        if (size < 0) {
            BIO_free_all(wbp);
            BIO_free_all(rbp);
            PKCS7_free(pkcs7);
            return NULL;
        } else if (size == 0) {
            break;
        }

        ret = BIO_write(wbp, buffer, size);
        if (ret != size) {
            BIO_free_all(wbp);
            BIO_free_all(rbp);
            PKCS7_free(pkcs7);
            return NULL;
        }
    }

    /* We only use the first signer even if there're multiple */
    signer = sk_PKCS7_SIGNER_INFO_value(signers, 0); /* Internal */
    if (scep_PKCS7_SIGNER_INFO_check_algo(signer)) {
        BIO_free_all(wbp);
        BIO_free_all(rbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    cert = PKCS7_cert_from_signer_info(pkcs7, signer); /* Internal */
    if (!cert || scep_check_signature_algo(X509_get_signature_nid(cert))) {
        BIO_free_all(wbp);
        BIO_free_all(rbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    if (PKCS7_signatureVerify(rbp, pkcs7, signer, cert) != 1) {
        BIO_free_all(wbp);
        BIO_free_all(rbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    BIO_free_all(rbp);

    signkey = X509_get0_pubkey(cert);
    if (!signkey) {
        BIO_free_all(wbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    signbits = scep_get_rsa_key_bits(signkey);
    if (signbits < SCEP_RSA_MIN_BITS) {
        BIO_free_all(wbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    /* Fail uncompliant client exposing secret information */
    if (PKCS7_get_signed_attribute(signer, NID_pkcs9_challengePassword)) {
        if (!allow_exposed_challenge_password) {
            BIO_free_all(wbp);
            PKCS7_free(pkcs7);
            return NULL;
        }
    }

    if (scep_decrypt(scep, &wbp)) {
        BIO_free_all(wbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    auth_attr = PKCS7_get_signed_attributes(signer); /* Internal */

    m = (struct scep_pkiMessage *)malloc(sizeof(*m));
    if (!m) {
        BIO_free_all(wbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    memset(m, 0, sizeof(*m));
    if (scep_pkiMessage_get_attributes(scep, &m->auth_attr, auth_attr)) {
        free(m);
        BIO_free_all(wbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    if (scep_pkiMessage_set_type(m)) {
        free(m);
        BIO_free_all(wbp);
        PKCS7_free(pkcs7);
        return NULL;
    }

    m->payload = wbp;
    m->signer = cert;
    m->pkcs7 = pkcs7;
    return m;
}

void scep_pkiMessage_free(struct scep_pkiMessage *m)
{
    if (!m) {
        return;
    }

    if (m->payload) {
        BIO_free_all(m->payload);
    }

    if (m->pkcs7) {
        PKCS7_free(m->pkcs7);
    }

    free(m);
}

static int scep_unhex_one(unsigned char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else {
        return -1;
    }
}

static int scep_unhex(unsigned char *s, unsigned int len, unsigned char *o)
{
    unsigned int i;
    int h;
    int l;

    for (i = 0; i < len; i += 2) {
        h = scep_unhex_one(s[i + 0]);
        l = scep_unhex_one(s[i + 1]);
        if (h < 0 || l < 0) {
            return -1;
        }

        o[i / 2] = (unsigned char)(h * 16 + l);
    }

    return 0;
}

static int scep_check_transactionID(
        X509_REQ *csr,
        ASN1_PRINTABLESTRING *transactionID)
{
    unsigned char expected[EVP_MAX_MD_SIZE];
    unsigned char actual[EVP_MAX_MD_SIZE];
    const EVP_MD *type;
    unsigned int len;
    EVP_PKEY *pkey;
    X509 *x509;

    if (transactionID->length < 0 || transactionID->length % 2) {
        return -1;
    }

    switch (transactionID->length / 2) {
    case MD5_DIGEST_LENGTH:    type = EVP_md5();    break;
    case SHA_DIGEST_LENGTH:    type = EVP_sha1();   break;
    case SHA256_DIGEST_LENGTH: type = EVP_sha256(); break;
    case SHA512_DIGEST_LENGTH: type = EVP_sha512(); break;
    default : return -1;
    }

    if (scep_unhex(transactionID->data, transactionID->length, expected)) {
        return -1;
    }

    pkey = X509_REQ_get0_pubkey(csr); /* Internal */
    if (!pkey) {
        return -1;
    }

    x509 = X509_new();
    if (!x509) {
        return -1;
    }

    if (X509_set_pubkey(x509, pkey) != 1) {
        X509_free(x509);
        return -1;
    }

    if (X509_pubkey_digest(x509, type, actual, &len) != 1) {
        X509_free(x509);
        return -1;
    }

    X509_free(x509);
    if (memcmp(expected, actual, len)) {
        return -1;
    }

    return 0;
}

static int scep_verify(X509 *issuer, X509 *subject)
{
    X509_STORE_CTX *ctx;
    X509_STORE *store;

    store = X509_STORE_new();
    if (!store) {
        return -1;
    }

    if (X509_STORE_add_cert(store, issuer) != 1) {
        X509_STORE_free(store);
        return -1;
    }

    ctx = X509_STORE_CTX_new();
    if (!ctx) {
        X509_STORE_free(store);
        return -1;
    }

    if (X509_STORE_CTX_init(ctx, store, subject, NULL) != 1) {
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        return -1;
    }

    if (X509_verify_cert(ctx) != 1) {
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        return 0;
    }

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return 1;
}

struct scep_PKCSReq *scep_PKCSReq_new(
        struct scep *scep,
        struct scep_pkiMessage *m)
{
    struct scep_pkiMessage_attributes *a;
    ASN1_PRINTABLESTRING *cp;
    struct scep_PKCSReq *req;
    X509_NAME *subject;
    EVP_PKEY *pkey;
    BUF_MEM *bptr;
    X509_REQ *csr;
    RSA *csrkey;
    int csrbits;
    BIO *robp;
    int valid;

    if (!scep || !scep->cert || !m) {
        return NULL;
    }

    valid = scep_verify(scep->cert, m->signer);
    if (valid < 0) {
        return NULL;
    }

    a = &m->auth_attr;
    if (!a->transactionID || !a->messageType || !a->senderNonce) {
        return NULL;
    }

    if (memcmp(a->messageType->data, "19", a->messageType->length)) {
        return NULL;
    }

    BIO_get_mem_ptr(m->payload, &bptr);
    robp = BIO_new_mem_buf(bptr->data, bptr->length);
    if (!robp) {
        return NULL;
    }

    csr = d2i_X509_REQ_bio(robp, NULL);
    if (!csr) {
        BIO_free_all(robp);
        return NULL;
    }

    BIO_free_all(robp);

    if (!(pkey = X509_REQ_get0_pubkey(csr))                         ||
        (csrbits = scep_get_rsa_key_bits(pkey)) < SCEP_RSA_MIN_BITS ||
        !(csrkey = EVP_PKEY_get0_RSA(X509_REQ_get0_pubkey(csr)))    ||
        !(subject = X509_REQ_get_subject_name(csr))                 ||
        X509_NAME_get_index_by_NID(subject, NID_commonName, -1) < 0 ){

        X509_REQ_free(csr);
        return NULL;
    }

    if (X509_REQ_verify(csr, pkey) != 1) {
        X509_REQ_free(csr);
        return NULL;
    }

    /* Enrollment, well formed transactionID is expected */
    if (scep_check_transactionID(csr, a->transactionID)) {
        X509_REQ_free(csr);
        return NULL;
    }

    cp = scep_get_req_printable_string(csr, NID_pkcs9_challengePassword);
    req = (struct scep_PKCSReq *)malloc(sizeof(*req));
    if (!req) {
        X509_REQ_free(csr);
        return NULL;
    }

    memset(req, 0, sizeof(*req));
    req->challengePassword = cp;
    req->csrkey = csrkey;
    req->valid = valid;
    req->csr = csr;
    req->m = m;
    return req;
}

void scep_PKCSReq_free(struct scep_PKCSReq *req)
{
    if (!req) {
        return;
    }

    if (req->csr) {
        X509_REQ_free(req->csr);
    }

    free(req);
}

const X509_REQ *scep_PKCSReq_get_csr(const struct scep_PKCSReq *req)
{
    if (!req) {
        return NULL;
    }

    return req->csr;
}

static int scep_add_ext(
        X509 *issuer,
        X509 *subject,
        int nid,
        const char *value)
{
    X509_EXTENSION *ext;
    X509V3_CTX ctx;

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, subject, NULL, NULL, X509V3_ADD_DEFAULT);

    ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ext) {
        return -1;
    }

    if (X509_add_ext(subject, ext, -1) != 1) {
        X509_EXTENSION_free(ext);
        return -1;
    }

    X509_EXTENSION_free(ext);
    return 0;
}

static int scep_set_serial(X509 *subject)
{
    ASN1_INTEGER *serial;
    BIGNUM *bn;

    bn = BN_new();
    if (!bn) {
        return -1;
    }

    if (BN_pseudo_rand(bn, 159, 0, 0) != 1) {
        BN_free(bn);
        return -1;
    }

    serial = BN_to_ASN1_INTEGER(bn, NULL);
    if (!serial) {
        BN_free(bn);
        return -1;
    }

    BN_free(bn);
    if (X509_set_serialNumber(subject, serial) != 1) {
        ASN1_INTEGER_free(serial);
        return -1;
    }

    ASN1_INTEGER_free(serial);
    return 0;
}

static int scep_set_not_before_not_after(
        time_t now,
        X509 *subject,
        long notBeforeDays,
        long notAfterDays)
{
    ASN1_TIME *t;

    t = ASN1_TIME_new();
    if (!t) {
        return -1;
    }

    if (!X509_time_adj_ex(t, notBeforeDays, 0, &now)) {
        ASN1_TIME_free(t);
        return -1;
    }

    if (X509_set1_notBefore(subject, t) != 1) {
        ASN1_TIME_free(t);
        return -1;
    }

    if (!X509_time_adj_ex(t, notAfterDays, 0, &now)) {
        ASN1_TIME_free(t);
        return -1;
    }

    if (X509_set1_notAfter(subject, t) != 1) {
        ASN1_TIME_free(t);
        return -1;
    }

    ASN1_TIME_free(t);
    return 0;
}

static int scep_add_default_extensions(X509 *issuer, X509 *subject)
{
    if (scep_add_ext(issuer, subject,
            NID_basic_constraints, "critical,CA:FALSE")   ||
        scep_add_ext(issuer, subject,
            NID_key_usage, "critical,digitalSignature")   ||
        scep_add_ext(issuer, subject,
            NID_ext_key_usage, "clientAuth")              ||
        scep_add_ext(issuer, subject,
            NID_subject_key_identifier, "hash")           ||
        scep_add_ext(issuer, subject,
            NID_authority_key_identifier, "keyid:always") ){
        return -1;
    }

    return 0;
}

static int scep_sign(
        time_t now,
        struct scep *scep,
        X509 *subject,
        long days)
{
    struct scep_extension *p;

    if (X509_set_version(subject, 2) != 1) { /* X509 V3 */
        return -1;
    }

    if (scep_set_serial(subject)) {
        return -1;
    }

    if (X509_set_issuer_name(subject,
            X509_get_subject_name(scep->cert)) != 1) {

        return -1;
    }

    if (scep_set_not_before_not_after(now, subject, 0, days)) {
        return -1;
    }

    if (!scep->extensions) { /* Not good, we should have something... */
        if (scep_add_default_extensions(scep->cert, subject)) {
            return -1;
        }
    }

    for (p = scep->extensions; p; p = p->next) {
        if (scep_add_ext(scep->cert, subject, p->nid, p->value)) {
            return -1;
        }
    }

    if (X509_sign(subject, scep->pkey, scep->md) == 0) {
        return -1;
    }

    return 0;
}

static int scep_pkiMessage_encrypt(BIO *input, BIO *output, X509 *recipient)
{
    STACK_OF(X509) *recipients;
    PKCS7 *pkcs7;

    recipients = sk_X509_new_null();
    if (!recipients) {
        return -1;
    }

    if (sk_X509_push(recipients, recipient) != 1) {
        sk_X509_free(recipients);
        return -1;
    }

    pkcs7 = PKCS7_encrypt(recipients, input, EVP_aes_256_cbc(), PKCS7_BINARY);
    if (!pkcs7) {
        sk_X509_free(recipients);
        return -1;
    }

    sk_X509_free(recipients);

    if (i2d_PKCS7_bio(output, pkcs7) != 1) {
        PKCS7_free(pkcs7);
        return -1;
    }

    PKCS7_free(pkcs7);
    return 0;
}

static PKCS7 *scep_pkiMessage_seal(
        struct scep *scep,
        BIO *payload,
        X509 *recipient,
        X509 *signer,
        EVP_PKEY *signkey,
        struct scep_pkiMessage_attributes *a)
{
    PKCS7_SIGNER_INFO *si;
    BIO *content;
    PKCS7 *pkcs7;

    pkcs7 = PKCS7_new();
    if (!pkcs7) {
        return NULL;
    }

    if (PKCS7_set_type(pkcs7, NID_pkcs7_signed) != 1) {
        PKCS7_free(pkcs7);
        return NULL;
    }

    if (PKCS7_add_certificate(pkcs7, signer) != 1) {
        PKCS7_free(pkcs7);
        return NULL;
    }

    si = PKCS7_add_signature(pkcs7, signer, signkey, EVP_sha1());
    if (!si) {
        PKCS7_free(pkcs7);
        return NULL;
    }

    if (scep_pkiMessage_add_attributes(scep, si, a)) {
        PKCS7_free(pkcs7);
        return NULL;
    }

    if (PKCS7_add_signed_attribute(si, NID_pkcs9_contentType,
            V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data)) != 1) {

        PKCS7_free(pkcs7);
        return NULL;
    }

    if (PKCS7_content_new(pkcs7, NID_pkcs7_data) != 1) {
        PKCS7_free(pkcs7);
        return NULL;
    }

    content = PKCS7_dataInit(pkcs7, NULL);
    if (!content) {
        PKCS7_free(pkcs7);
        return NULL;
    }

    if (payload) {
        if (scep_pkiMessage_encrypt(payload, content, recipient)) {
            BIO_free_all(content);
            PKCS7_free(pkcs7);
            return NULL;
        }
    }

    if (PKCS7_dataFinal(pkcs7, content) != 1) {
        BIO_free_all(content);
        PKCS7_free(pkcs7);
        return NULL;
    }

    BIO_free_all(content);
    return pkcs7;
}

static int scep_degenerate_chain(BIO *bp, STACK_OF(X509) *certs)
{
    PKCS7_SIGNED *p7s;
    PKCS7 *pkcs7;

    pkcs7 = PKCS7_new();
    if (!pkcs7) {
        return -1;
    }

    if (PKCS7_set_type(pkcs7, NID_pkcs7_signed) != 1) {
        PKCS7_free(pkcs7);
        return -1;
    }

    p7s = pkcs7->d.sign;
    if (ASN1_INTEGER_set(p7s->version, 1) != 1) {
        PKCS7_free(pkcs7);
        return -1;
    }

    p7s->contents->type = OBJ_nid2obj(NID_pkcs7_data);
    if (!p7s->contents->type) {
        PKCS7_free(pkcs7);
        return -1;
    }

    p7s->cert = certs;
    if (i2d_PKCS7_bio(bp, pkcs7) != 1) {
        p7s->cert = NULL;
        PKCS7_free(pkcs7);
        return -1;
    }

    p7s->cert = NULL;
    PKCS7_free(pkcs7);
    return 0;
}

static int scep_degenerate_va(BIO *bp, va_list ap)
{
    STACK_OF(X509) *chain;
    X509 *cert;
    int ret;

    chain = sk_X509_new_null();
    if (!chain) {
        return -1;
    }

    while ((cert = va_arg(ap, X509 *))) {
        if (sk_X509_push(chain, cert) == 0) {
            sk_X509_free(chain);
            return -1;
        }
    }

    ret = scep_degenerate_chain(bp, chain);
    sk_X509_free(chain);
    return ret;
}

static int scep_degenerate(BIO *bp, ...)
{
    va_list ap;
    int ret;

    va_start(ap, bp);
    ret = scep_degenerate_va(bp, ap);
    va_end(ap);

    return ret;
}

static int scep_CertRep_set_SAN(X509_REQ *req, X509 *subject)
{
    STACK_OF(X509_EXTENSION) *exts;
    X509_EXTENSION *ext;
    ASN1_OBJECT *obj;
    int count;
    int ret;
    int i;

    exts = X509_REQ_get_extensions(req);
    if (!exts) {
        return 0;
    }

    count = sk_X509_EXTENSION_num(exts);
    for (i = 0, ret = 0; i < count; ++i) {
        ext = sk_X509_EXTENSION_value(exts, i);
        obj = X509_EXTENSION_get_object(ext);
        if (OBJ_obj2nid(obj) != NID_subject_alt_name) {
            continue;
        }

        if (X509_add_ext(subject, ext, -1) != 1) {
            ret = -1;
            break;
        }
    }

    for (i = 0, ret = 0; i < count; ++i) {
        X509_EXTENSION_free(sk_X509_EXTENSION_value(exts, i));
    }

    sk_X509_EXTENSION_free(exts);
    return ret;
}

static PKCS7 *scep_CertRep_seal(
        struct scep *scep,
        struct scep_PKCSReq *req,
        const char *pkiStatus,
        const char *failInfo,
        X509 *subject)
{
    struct scep_pkiMessage_attributes auth_attr;
    PKCS7 *pkcs7;
    BIO *payload;

    payload = NULL;
    if (subject) {
        payload = BIO_new(BIO_s_mem());
        if (!payload) {
            return NULL;
        }

        if (scep_degenerate(payload, subject, NULL)) {
            BIO_free_all(payload);
            return NULL;
        }
    }

    memset(&auth_attr, 0, sizeof(auth_attr));
    auth_attr.transactionID = ASN1_STRING_dup(req->m->auth_attr.transactionID);
    auth_attr.messageType = scep_printable_string("3");
    auth_attr.pkiStatus = scep_printable_string(pkiStatus);
    auth_attr.senderNonce = scep_nonce();
    auth_attr.recipientNonce = ASN1_STRING_dup(req->m->auth_attr.senderNonce);

    if (failInfo) {
        auth_attr.failInfo = scep_printable_string(failInfo);
    }

    if (!auth_attr.transactionID          ||
        !auth_attr.messageType            ||
        !auth_attr.senderNonce            ||
        !auth_attr.recipientNonce         ||
        !auth_attr.pkiStatus              ||
        (failInfo && !auth_attr.failInfo) ){

        scep_pkiMessage_attributes_cleanup(&auth_attr);
        BIO_free_all(payload);
        return NULL;
    }

    pkcs7 = scep_pkiMessage_seal(
            scep,
            payload,
            req->m->signer,
            scep->cert,
            scep->pkey,
            &auth_attr);

    if (!pkcs7) {
        scep_pkiMessage_attributes_cleanup(&auth_attr);
        BIO_free_all(payload);
        return NULL;
    }

    scep_pkiMessage_attributes_cleanup(&auth_attr);
    BIO_free_all(payload);
    return pkcs7;
}

struct scep_CertRep *scep_CertRep_new(
        struct scep *scep, struct scep_PKCSReq *req, time_t now, long days)
{
    struct scep_CertRep *rep;
    X509_NAME *name;
    EVP_PKEY *pkey;
    X509 *subject;

    if (!scep || !scep->cert || !scep->pkey || !req) {
        return NULL;
    }

    name = X509_REQ_get_subject_name(req->csr);
    if (!name) {
        return NULL;
    }

    pkey = X509_REQ_get0_pubkey(req->csr);
    if (!pkey) {
        return NULL;
    }

    subject = X509_new();
    if (!subject) {
        return NULL;
    }

    if (X509_set_subject_name(subject, name) != 1 ||
        X509_set_pubkey(subject, pkey) != 1       ){

        X509_free(subject);
        return NULL;
    }

    if (scep_CertRep_set_SAN(req->csr, subject)) {
        X509_free(subject);
        return NULL;
    }

    if (scep_sign(now, scep, subject, days)) {
        X509_free(subject);
        return NULL;
    }

    rep = (struct scep_CertRep *)malloc(sizeof(*rep));
    if (!rep) {
        X509_free(subject);
        return NULL;
    }

    memset(rep, 0, sizeof(*rep));
    rep->cert = subject;
    rep->pkcs7 = scep_CertRep_seal(scep, req, "0", NULL, subject);
    if (!rep->pkcs7) {
        free(rep);
        X509_free(subject);
        return NULL;
    }

    return rep;
}

struct scep_CertRep *scep_CertRep_reject(
        struct scep *scep, struct scep_PKCSReq *req, enum failInfo why)
{
    struct scep_CertRep *rep;
    const char *failInfo;

    if (!scep || !scep->cert || !scep->pkey || !req) {
        return NULL;
    }

    rep = (struct scep_CertRep *)malloc(sizeof(*rep));
    if (!rep) {
        return NULL;
    }

    switch (why) {
    case failInfo_badAlg         : failInfo =  "0"; break;
    case failInfo_badMessageCheck: failInfo =  "1"; break;
    case failInfo_badRequest     : failInfo =  "2"; break;
    case failInfo_badTime        : failInfo =  "3"; break;
    case failInfo_badCertId      : failInfo =  "4"; break;
    default                      : failInfo = NULL; break;
    }

    memset(rep, 0, sizeof(*rep));
    rep->pkcs7 = scep_CertRep_seal(scep, req, "2", failInfo, NULL);
    if (!rep->pkcs7) {
        free(rep);
        return NULL;
    }

    return rep;
}

X509 *scep_CertRep_get_subject(struct scep_CertRep *rep)
{
    if (!rep) {
        return NULL;
    }

    return rep->cert;
}

int scep_CertRep_save(struct scep_CertRep *rep, BIO *bp)
{
    if (!rep || !bp) {
        return -1;
    }

    if (i2d_PKCS7_bio(bp, rep->pkcs7) != 1) {
        return -1;
    }

    return 0;
}

void scep_CertRep_free(struct scep_CertRep *rep)
{
    if (!rep) {
        return;
    }

    if (rep->cert) {
        X509_free(rep->cert);
    }

    if (rep->pkcs7) {
        PKCS7_free(rep->pkcs7);
    }

    free(rep);
}

int scep_get_cert(struct scep *scep, BIO *bp)
{
    int num;

    if (!scep || !scep->chain) {
        return -1;
    }

    num = sk_X509_num(scep->chain);
    if (num <= 0) {
        return -1;

    } else if (num == 1) {
        if (i2d_X509_bio(bp, scep->cert) != 1) {
            return -1;
        }
        return 1;

    } else if (scep_degenerate_chain(bp, scep->chain)) {
        return -1;
    }

    return num;
}

const ASN1_PRINTABLESTRING *scep_PKCSReq_get_challengePassword(
        const struct scep_PKCSReq *req)
{
    if (!req) {
        return NULL;
    }

    return req->challengePassword;
}

const RSA *scep_PKCSReq_get_csr_key(const struct scep_PKCSReq *req)
{
    if (!req) {
        return NULL;
    }

    return req->csrkey;
}

const X509 *scep_PKCSReq_get_current_certificate(
        const struct scep_PKCSReq *req)
{
    if (!req || !req->valid) {
        return NULL;
    }

    return req->m->signer;
}

enum messageType scep_pkiMessage_get_type(const struct scep_pkiMessage *m)
{
    return m->messageType;
}
