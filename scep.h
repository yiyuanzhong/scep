#ifndef SCEP_H
#define SCEP_H

#include <openssl/bio.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

struct scep;
struct scep_PKCSReq;
struct scep_CertRep;
struct scep_pkiMessage;

enum messageType {
    messageType_PKCSReq         = 19,
    messageType_CertRep         = 3,
    messageType_GetCertInitial  = 20,
    messageType_GetCert         = 21,
    messageType_GetCRL          = 22,
};

enum pkiStatus {
    pkiStatus_SUCCESS           = 0,
    pkiStatus_FAILURE           = 2,
    pkiStatus_PENDING           = 3,
};

enum failInfo {
    failInfo_badAlg             = 0,
    failInfo_badMessageCheck    = 1,
    failInfo_badRequest         = 2,
    failInfo_badTime            = 3,
    failInfo_badCertId          = 4,
};

extern struct scep *scep_new(void);
extern void scep_free(struct scep *scep);

/* Load signing certificate first */
extern int scep_load_certificate(
        struct scep *scep,
        const char *certfile,
        int certpem,
        const char *keyfile,
        int keypem,
        const char *keypass);

/* Then load certificate chain if needed */
extern int scep_load_certificate_chain(
        struct scep *scep,
        const char *certfile,
        int certpem);

extern int scep_load_subject_extensions(
        struct scep *scep, const char *filename);

/* Returns number of certificates included, or -1 for error */
extern int scep_get_cert(struct scep *scep, BIO *bp);

extern struct scep_pkiMessage *scep_pkiMessage_new(struct scep *scep, BIO *bp,
        int allow_exposed_challenge_password); /* macOS bug */

extern enum messageType scep_pkiMessage_get_type(
        const struct scep_pkiMessage *m);

extern void scep_pkiMessage_free(struct scep_pkiMessage *m);

extern struct scep_PKCSReq *scep_PKCSReq_new(
        struct scep *scep, struct scep_pkiMessage *m);

extern void scep_PKCSReq_free(struct scep_PKCSReq *req);

extern const X509_REQ *scep_PKCSReq_get_csr(const struct scep_PKCSReq *req);
extern const RSA *scep_PKCSReq_get_csr_key(const struct scep_PKCSReq *req);

extern const ASN1_PRINTABLESTRING *scep_PKCSReq_get_challengePassword(
        const struct scep_PKCSReq *req);

/* Only if the requester used a valid certificate issued by this CA */
extern const X509 *scep_PKCSReq_get_current_certificate(
        const struct scep_PKCSReq *req);

extern X509 *scep_CertRep_get_subject(struct scep_CertRep *rep);
extern int scep_CertRep_save(struct scep_CertRep *rep, BIO *bp);
extern void scep_CertRep_free(struct scep_CertRep *rep);

extern struct scep_CertRep *scep_CertRep_new(
        struct scep *scep,
        struct scep_PKCSReq *req,
        time_t now,
        long days);

extern struct scep_CertRep *scep_CertRep_reject(
        struct scep *scep,
        struct scep_PKCSReq *req,
        enum failInfo why);

#ifdef __cplusplus
}
#endif

#endif /* SCEP_H */
